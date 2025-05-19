#!/bin/bash

LOGFILE="checagem_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1

UPDATE_MODE=0
if [[ "$1" == "--update" ]]; then
    UPDATE_MODE=1
    echo "⚙️ Modo update ativo: irá adicionar bloqueios .git e server_tokens off e recarregar nginx"
else
    echo "⚙️ Modo leitura apenas: não fará alterações"
fi

echo "====== 🚨 AUDITORIA DE SEGURANÇA - INÍCIO ======"

# Função para mostrar status no console (OK / ALERTA)
status_console() {
    local status=$1
    local msg=$2
    if [[ "$status" == "OK" ]]; then
        echo "[OK] $msg"
    else
        echo "[ALERTA] $msg"
    fi
}

# 0. Ver versão do Linux
echo -e "\n[0] Versão do Linux:"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "Distribuição: $NAME"
    echo "Versão: $VERSION"
    if [[ "$NAME" == "Ubuntu" ]]; then
        VNUM=$(echo "$VERSION_ID" | cut -d'.' -f1)
        if [ "$VNUM" -lt 20 ]; then
            status_console "ALERTA" "Ubuntu $VERSION_ID é antigo, recomendável atualizar para 20.04 ou superior."
        else
            status_console "OK" "Ubuntu $VERSION_ID atual."
        fi
    fi
else
    echo "Não foi possível detectar a versão do Linux."
fi

# 0.1 Verificações de versão de softwares
declare -A softwares
softwares=(
    [nginx]="nginx -v"
    [apache2]="apache2 -v"
    [php]="php -v"
    [mysql]="mysql --version"
)

for prog in "${!softwares[@]}"; do
    CMD=${softwares[$prog]}
    VERS=$($CMD 2>&1 | head -1)
    echo "$prog: $VERS"
    case $prog in
        nginx)
            echo "$VERS" | grep -qE "1\\.14\\.0|1\\.16\\.1" && status_console "ALERTA" "nginx com versão vulnerável"
            ;;
        apache2)
            echo "$VERS" | grep -qE "2\\.4\\.29" && status_console "ALERTA" "apache2 com versão vulnerável"
            ;;
        php)
            echo "$VERS" | grep -qE "7\\.2\\." && status_console "ALERTA" "PHP 7.2 desatualizado"
            ;;
        mysql)
            echo "$VERS" | grep -qE "5\\.7\\." && status_console "ALERTA" "MySQL 5.7 antigo"
            ;;
    esac
done

# Verificações de usuários, shell, root, logins e senhas
echo -e "\n[1] Usuários com shell válido:"
awk -F: '/\/bin\/bash|\/bin\/sh/ {print $1}' /etc/passwd

echo -e "\n[2] Usuários com UID 0 além do root:"
awk -F: '($3 == 0) {print $1}' /etc/passwd

echo -e "\n[3] Últimos logins:"
lastlog | grep -v "Never"

echo -e "\n[4] Contas com senha desabilitada:"
awk -F: '($2 == "!" || $2 == "*") {print $1}' /etc/shadow

echo -e "\n[5] Contas com senha vazia:"
awk -F: '($2 == "") {print $1}' /etc/shadow

echo -e "\n[6] Verificando authorized_keys:"
find /home -name "authorized_keys" -exec ls -l {} \;

echo -e "\n[7] Root pode logar por SSH?"
grep -i "^PermitRootLogin" /etc/ssh/sshd_config

echo -e "\n[8] Firewall UFW está ativado?"
ufw status

echo -e "\n[9] Portas escutando:"
ss -tuln

echo -e "\n[10] Serviços escutando em 0.0.0.0:"
ss -tuln | grep "0.0.0.0"

echo -e "\n[11] PHP instalado?"
php -v 2>/dev/null || echo "❌ PHP não instalado."

echo -e "\n[12] Versões de PHP instaladas:"
ls /etc/php/ 2>/dev/null || echo "Nenhuma versão detectada."

echo -e "\n[13] Extensões perigosas habilitadas:"
php -m 2>/dev/null | grep -E 'exec|shell_exec|system|passthru|proc_open'

echo -e "\n[14] Procurando arquivos phpinfo():"
grep -rl "phpinfo" /var/www 2>/dev/null || echo "Nenhum phpinfo encontrado."

echo -e "\n[15] Procurando .git em /var/www:"
find /var/www -type d -name ".git"

echo -e "\n[16] Servidores ativos:"
systemctl is-active nginx && echo "✔️ NGINX ativo" || echo "❌ NGINX inativo"
systemctl is-active apache2 && echo "✔️ Apache ativo" || echo "❌ Apache inativo"

echo -e "\n[17] Validando arquivos de config Nginx:"
nginx -t

echo -e "\n[18] Validando arquivos de config Apache:"
apachectl configtest 2>/dev/null

# 19. Verificação de bloqueio .git e server_tokens
SITES_SEM_GIT=()
NGINX_SEM_SERVER_TOKENS=()

for conf in /etc/nginx/sites-enabled/*; do
    [ -f "$conf" ] || continue
    if grep -qE '\.git' "$conf"; then
        status_console "OK" "$conf bloqueia acesso a .git"
    else
        status_console "ALERTA" "$conf NÃO bloqueia acesso a .git"
        SITES_SEM_GIT+=("$conf")
    fi
done

if grep -q -E '^\s*server_tokens\s+off;' /etc/nginx/nginx.conf; then
    status_console "OK" "server_tokens está OFF no nginx.conf"
else
    status_console "ALERTA" "server_tokens NÃO está OFF no nginx.conf"
    NGINX_SEM_SERVER_TOKENS+=("/etc/nginx/nginx.conf")
fi

if [ "$UPDATE_MODE" -eq 1 ]; then
    for conf in "${SITES_SEM_GIT[@]}"; do
        echo "Adicionando bloqueio .git em $conf"
        echo -e "\nlocation ~ /\\.git {\n    deny all;\n    access_log off;\n    log_not_found off;\n}" >> "$conf"
    done

    if [ ${#NGINX_SEM_SERVER_TOKENS[@]} -gt 0 ]; then
        sed -i '/http {/a \\tserver_tokens off;' /etc/nginx/nginx.conf
        status_console "OK" "Adicionado 'server_tokens off;' no nginx.conf"
    fi

    echo "Recarregando nginx..."
    nginx -t && systemctl reload nginx && status_console "OK" "Nginx recarregado" || status_console "ALERTA" "Erro ao recarregar nginx"
fi

# 20. Ferramentas de acesso remoto
for tool in ngrok teamviewer anydesk dwservice remmina rustdesk; do
    if command -v $tool >/dev/null 2>&1; then
        status_console "ALERTA" "Ferramenta de acesso remoto detectada: $tool"
    fi
done

# 21. Inicializações automáticas
echo "📄 /etc/rc.local:"
[ -f /etc/rc.local ] && cat /etc/rc.local || echo "Não existe"
echo "\n📁 /etc/init.d/:"
ls -1 /etc/init.d/
echo "\n📁 systemd (custom services):"
systemctl list-unit-files | grep enabled | grep -vE "nginx|apache|ssh|ufw"

# 22. Crontabs
echo "\n⏰ Itens no crontab de todos os usuários:"
for u in $(cut -f1 -d: /etc/passwd); do
    crontab -u $u -l 2>/dev/null && echo "--- ($u)" || true
done

echo -e "\n====== ✅ AUDITORIA DE SEGURANÇA - FIM ======"
