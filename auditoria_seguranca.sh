#!/bin/bash

echo "====== 🚨 AUDITORIA DE SEGURANÇA - INÍCIO ======"

LOGFILE="checagem_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "\nEsse relatório estará salvo com nome $LOGFILE"

echo "\n=== Verificações básicas e segurança - Servidor Ubuntu ==="

# 0. Ver versão do Linux
echo -e "\n[0] Versão do Linux:"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "Distribuição: $NAME"
    echo "Versão: $VERSION"
    # Exemplo básico para Ubuntu
    if [[ "$NAME" == "Ubuntu" ]]; then
        VNUM=$(echo "$VERSION_ID" | cut -d'.' -f1)
        if [ "$VNUM" -lt 20 ]; then
            echo "[ALERTA] Versão Ubuntu $VERSION_ID é antiga, recomendo upgrade para 20.04 ou superior."
        else
            echo "[OK] Versão Ubuntu $VERSION_ID atual."
        fi
    fi
else
    echo "Não foi possível detectar a versão do Linux."
fi

# 0.1 Versões principais e alertas simples
echo -e "\n[0.1] Versões dos principais softwares:"
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

    # Exemplos simples de alertas
    case $prog in
        nginx)
            if echo "$VERS" | grep -qE "1\.14\.0|1\.16\.1"; then
                echo "[ALERTA] Versão do nginx com vulnerabilidade conhecida, atualizar."
            fi
            ;;
        apache2)
            if echo "$VERS" | grep -qE "2\.4\.29"; then
                echo "[ALERTA] Versão do apache2 com vulnerabilidade conhecida, atualizar."
            fi
            ;;
        php)
            if echo "$VERS" | grep -qE "7\.2\."; then
                echo "[ALERTA] Versão PHP 7.2 tem fim de suporte e falhas, atualizar."
            fi
            ;;
        mysql)
            if echo "$VERS" | grep -qE "5\.7\."; then
                echo "[ALERTA] Versão MySQL 5.7 é antiga e pode ter falhas, considerar upgrade."
            fi
            ;;
    esac
done

echo -e "\n🔐 [1] Usuários com shell válido:"
awk -F: '/\/bin\/bash|\/bin\/sh/ {print $1}' /etc/passwd

echo -e "\n⚠️ [2] Usuários com UID 0 além do root:"
awk -F: '($3 == 0) {print $1}' /etc/passwd

echo -e "\n📆 [3] Últimos logins de usuários:"
lastlog | grep -v "Never"

echo -e "\n🔑 [4] Contas com senha desabilitada:"
awk -F: '($2 == "!" || $2 == "*") {print $1}' /etc/shadow

echo -e "\n❌ [5] Contas com senha vazia:"
awk -F: '($2 == "") {print $1}' /etc/shadow

echo -e "\n🕵️ [6] Verificando authorized_keys abertos:"
find /home -name "authorized_keys" -exec ls -l {} \;

echo -e "\n🧪 [7] Root pode logar por SSH?"
grep -i "^PermitRootLogin" /etc/ssh/sshd_config

echo -e "\n🛡️ [8] Firewall UFW está ativado?"
ufw status

echo -e "\n🌍 [9] Portas escutando:"
ss -tuln

echo -e "\n🌐 [10] Serviços escutando em 0.0.0.0:"
ss -tuln | grep "0.0.0.0"

echo -e "\n🧩 [11] PHP instalado?"
php -v 2>/dev/null || echo "❌ PHP não instalado."

echo -e "\n📦 [12] Versões de PHP instaladas:"
ls /etc/php/ 2>/dev/null || echo "Nenhuma versão detectada."

echo -e "\n🔍 [13] Extensões perigosas habilitadas:"
php -m 2>/dev/null | grep -E 'exec|shell_exec|system|passthru|proc_open'

echo -e "\n📁 [14] Procurando arquivos phpinfo():"
grep -rl "phpinfo" /var/www 2>/dev/null || echo "Nenhum phpinfo encontrado."

echo -e "\n📂 [15] Procurando .git em /var/www:"
find /var/www -type d -name ".git"

echo -e "\n🌐 [16] Servidores ativos:"
systemctl is-active nginx && echo "✔️ NGINX ativo" || echo "❌ NGINX inativo"
systemctl is-active apache2 && echo "✔️ Apache ativo" || echo "❌ Apache inativo"

echo -e "\n📄 [17] Validando arquivos de config Nginx:"
nginx -t

echo -e "\n📄 [18] Validando arquivos de config Apache:"
apachectl configtest 2>/dev/null

echo -e "\n🚫 [19] Verificando sites do Nginx sem bloqueio de .git:"
ENCONTRADOS=0
SITES_SEM_GIT=()
for conf in /etc/nginx/sites-enabled/*; do
    [ -f "$conf" ] || continue
    if grep -qE '\.git' "$conf"; then
        echo "[OK] $conf bloqueia .git"
    else
        echo "[FALHA] $conf NÃO bloqueia .git"
        ((ENCONTRADOS++))
        SITES_SEM_GIT+=("$conf")
    fi
done
if [ $ENCONTRADOS -eq 0 ]; then
    echo "✅ Todos os sites têm bloqueio .git"
else
    echo "❌ $ENCONTRADOS site(s) sem bloqueio .git"
    read -p "Quer adicionar bloqueio .git nesses arquivos? (s/n): " resp
    if [[ "$resp" =~ ^[Ss]$ ]]; then
        for file in "${SITES_SEM_GIT[@]}"; do
            echo "Adicionando bloqueio .git em $file"
            echo -e "\n# Bloqueio .git\nlocation ~ /\.git {\n    deny all;\n    access_log off;\n    log_not_found off;\n}" | sudo tee -a "$file"
        done
        echo "Recarregando nginx..."
        sudo nginx -t && sudo systemctl reload nginx
    fi
fi

echo -e "\n🕳️ [20] Procurando ferramentas de acesso remoto:"
for tool in ngrok teamviewer anydesk dwservice remmina rustdesk; do
    if command -v $tool >/dev/null 2>&1; then
        echo "⚠️ Ferramenta detectada: $tool"
    fi
done

echo -e "\n🗂️ [21] Verificando inicializações automáticas:"
echo "📄 /etc/rc.local:"
[ -f /etc/rc.local ] && cat /etc/rc.local || echo "Não existe"
echo -e "\n📁 /etc/init.d/:"
ls -1 /etc/init.d/
echo -e "\n📁 systemd (custom services):"
systemctl list-unit-files | grep enabled | grep -vE "nginx|apache|ssh|ufw"

echo -e "\n⏰ [22] Itens no crontab de todos os usuários:"
for u in $(cut -f1 -d: /etc/passwd); do
    crontab -u $u -l 2>/dev/null && echo "--- ($u)" || true
done

echo -e "\n🧼 [23] Deseja atualizar o sistema agora? (apt update) [s/n]"
read -r RESPOSTA
if [[ "$RESPOSTA" == "s" || "$RESPOSTA" == "S" ]]; then
    apt update 
else
    echo "🔕 Atualização ignorada."
fi

echo -e "\n🔍 [24] Validando se server_tokens está OFF em nginx:"
FILES_WITHOUT_SERVER_TOKENS=()
FILES_WITH_SERVER_TOKENS=()

for f in $(find /etc/nginx -type f -name "*.conf"); do
    if grep -q "server_tokens off;" "$f"; then
        FILES_WITH_SERVER_TOKENS+=("$f")
    else
        FILES_WITHOUT_SERVER_TOKENS+=("$f")
    fi
done

if [ ${#FILES_WITH_SERVER_TOKENS[@]} -gt 0 ]; then
    echo "✅ server_tokens off está configurado em:"
    for f in "${FILES_WITH_SERVER_TOKENS[@]}"; do echo "  $f"; done
else
    echo "❌ Nenhum arquivo com server_tokens off encontrado!"
fi

if [ ${#FILES_WITHOUT_SERVER_TOKENS[@]} -gt 0 ]; then
    echo "⚠️ Arquivos sem server_tokens off:"
    for f in "${FILES_WITHOUT_SERVER_TOKENS[@]}"; do echo "  $f"; done

    echo -n "Quer adicionar 'server_tokens off;' nestes arquivos? [s/n]: "
    read -r RESP_ST
    if [[ "$RESP_ST" =~ ^[sS]$ ]]; then
        for f in "${FILES_WITHOUT_SERVER_TOKENS[@]}"; do
            echo -e "\nserver_tokens off;" >> "$f"
            echo "[+] Adicionado server_tokens off em $f"
        done
        echo "⏳ Validando config nginx..."
        nginx -t
        echo "🔄 Reiniciando nginx..."
        systemctl reload nginx
    else
        echo "❌ Não foi adicionado server_tokens off."
    fi
else
    echo "👍 Todos os arquivos já possuem server_tokens off."
fi

echo -e "\n====== ✅ AUDITORIA DE SEGURANÇA - FIM ======"
