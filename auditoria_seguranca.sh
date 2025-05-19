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

# 0. Versão do Linux
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$NAME" == "Ubuntu" ]]; then
        VNUM=$(echo "$VERSION_ID" | cut -d'.' -f1)
        if [ "$VNUM" -lt 20 ]; then
            status_console "ALERTA" "Versão Ubuntu $VERSION_ID é antiga, recomendo upgrade para 20.04 ou superior."
        else
            status_console "OK" "Versão Ubuntu $VERSION_ID atual."
        fi
    else
        status_console "OK" "Linux: $NAME $VERSION"
    fi
else
    status_console "ALERTA" "Não foi possível detectar a versão do Linux."
fi

# 0.1 Versões dos principais softwares
declare -A softwares=(
    [nginx]="nginx -v"
    [apache2]="apache2 -v"
    [php]="php -v"
    [mysql]="mysql --version"
)

for prog in "${!softwares[@]}"; do
    CMD=${softwares[$prog]}
    VERS=$($CMD 2>&1 | head -1)

    alert=0
    case $prog in
        nginx)
            if echo "$VERS" | grep -qE "1\.14\.0|1\.16\.1"; then alert=1; fi
            ;;
        apache2)
            if echo "$VERS" | grep -qE "2\.4\.29"; then alert=1; fi
            ;;
        php)
            if echo "$VERS" | grep -qE "7\.2\."; then alert=1; fi
            ;;
        mysql)
            if echo "$VERS" | grep -qE "5\.7\."; then alert=1; fi
            ;;
    esac

    if [ $alert -eq 1 ]; then
        status_console "ALERTA" "Versão do $prog com vulnerabilidade conhecida: $VERS"
    else
        status_console "OK" "$prog: $VERS"
    fi
done

# 1. Usuários com shell válido
VALID_USERS=$(awk -F: '/\/bin\/bash|\/bin\/sh/ {print $1}' /etc/passwd)
if [[ -n $VALID_USERS ]]; then
    status_console "OK" "Usuários com shell válido encontrados"
else
    status_console "ALERTA" "Nenhum usuário com shell válido encontrado"
fi

# 2. Usuários com UID 0 além do root
UID0_USERS=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$')
if [[ -n $UID0_USERS ]]; then
    status_console "ALERTA" "Usuários com UID 0 além do root: $UID0_USERS"
else
    status_console "OK" "Nenhum usuário com UID 0 além do root"
fi

# 3. Últimos logins
LASTLOG=$(lastlog | grep -v "Never")
if [[ -n $LASTLOG ]]; then
    status_console "OK" "Últimos logins registrados"
else
    status_console "ALERTA" "Nenhum login registrado"
fi

# 4. Contas com senha desabilitada
PWD_DISABLED=$(awk -F: '($2 == "!" || $2 == "*") {print $1}' /etc/shadow)
if [[ -n $PWD_DISABLED ]]; then
    status_console "ALERTA" "Contas com senha desabilitada: $PWD_DISABLED"
else
    status_console "OK" "Nenhuma conta com senha desabilitada"
fi

# 5. Contas com senha vazia
PWD_EMPTY=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
if [[ -n $PWD_EMPTY ]]; then
    status_console "ALERTA" "Contas com senha vazia: $PWD_EMPTY"
else
    status_console "OK" "Nenhuma conta com senha vazia"
fi

# 6. authorized_keys abertos
AUTH_KEYS=$(find /home -name "authorized_keys" -exec ls -l {} \;)
if [[ -n $AUTH_KEYS ]]; then
    status_console "OK" "authorized_keys encontrados e listados no log"
else
    status_console "ALERTA" "Nenhum authorized_keys encontrado"
fi

# 7. Root pode logar por SSH?
SSH_ROOT=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config)
if [[ "$SSH_ROOT" =~ "no" ]]; then
    status_console "OK" "Login root via SSH desabilitado"
else
    status_console "ALERTA" "Login root via SSH habilitado"
fi

# 8. Firewall UFW ativado?
UFW_STATUS=$(ufw status | head -1)
if [[ "$UFW_STATUS" == *"inactive"* ]]; then
    status_console "ALERTA" "Firewall UFW está inativo"
else
    status_console "OK" "Firewall UFW está ativo"
fi

# 9. Portas escutando
PORTS=$(ss -tuln)
if [[ -n $PORTS ]]; then
    status_console "OK" "Portas escutando detectadas (detalhes no log)"
else
    status_console "ALERTA" "Nenhuma porta escutando detectada"
fi

# 10. Serviços escutando em 0.0.0.0
PORTS_ALL=$(ss -tuln | grep "0.0.0.0")
if [[ -n $PORTS_ALL ]]; then
    status_console "OK" "Serviços escutando em 0.0.0.0 (detalhes no log)"
else
    status_console "ALERTA" "Nenhum serviço escutando em 0.0.0.0 detectado"
fi

# 11. PHP instalado?
php -v &>/dev/null
if [ $? -eq 0 ]; then
    status_console "OK" "PHP instalado"
else
    status_console "ALERTA" "PHP não instalado"
fi

# 12. Versões PHP instaladas
PHP_VERSIONS=$(ls /etc/php/ 2>/dev/null)
if [[ -n $PHP_VERSIONS ]]; then
    status_console "OK" "Versões PHP instaladas: $PHP_VERSIONS"
else
    status_console "ALERTA" "Nenhuma versão PHP detectada"
fi

# 13. Extensões PHP perigosas habilitadas
PHP_DANGERS=$(php -m 2>/dev/null | grep -E 'exec|shell_exec|system|passthru|proc_open')
if [[ -n $PHP_DANGERS ]]; then
    status_console "ALERTA" "Extensões PHP perigosas habilitadas: $PHP_DANGERS"
else
    status_console "OK" "Nenhuma extensão PHP perigosa habilitada"
fi

# 14. Arquivos phpinfo() em /var/www
PHPINFO_FILES=$(grep -rl "phpinfo" /var/www 2>/dev/null)
if [[ -n $PHPINFO_FILES ]]; then
    status_console "ALERTA" "Arquivos com phpinfo() encontrados (lista no log)"
else
    status_console "OK" "Nenhum arquivo phpinfo() encontrado"
fi

# 15. Diretórios .git em /var/www
GIT_DIRS=$(find /var/www -type d -name ".git" 2>/dev/null)
if [[ -n $GIT_DIRS ]]; then
    status_console "ALERTA" "Diretórios .git encontrados em /var/www (detalhes no log)"
else
    status_console "OK" "Nenhum diretório .git encontrado em /var/www"
fi

# 16. Serviços ativos nginx e apache
systemctl is-active nginx &>/dev/null
NGINX_STATUS=$?
systemctl is-active apache2 &>/dev/null
APACHE_STATUS=$?

if [ $NGINX_STATUS -eq 0 ]; then
    status_console "OK" "NGINX ativo"
else
    status_console "ALERTA" "NGINX inativo"
fi

if [ $APACHE_STATUS -eq 0 ]; then
    status_console "OK" "Apache ativo"
else
    status_console "ALERTA" "Apache inativo"
fi

# 17. Validar config Nginx
NGINX_TEST=$(nginx -t 2>&1)
if echo "$NGINX_TEST" | grep -q "successful"; then
    status_console "OK" "Configuração nginx válida"
else
    status_console "ALERTA" "Configuração nginx inválida (detalhes no log)"
fi

# 18. Validar config Apache
APACHE_TEST=$(apachectl configtest 2>&1)
if echo "$APACHE_TEST" | grep -q "Syntax OK"; then
    status_console "OK" "Configuração apache válida"
else
    status_console "ALERTA" "Configuração apache inválida (detalhes no log)"
fi

# 19. Verificar bloqueio .git em sites-enabled do nginx
SITES_SEM_GIT=()
for conf in /etc/nginx/sites-enabled/*; do
    [ -f "$conf" ] || continue
    if grep -qE '\.git' "$conf"; then
        status_console "OK" "$conf bloqueia .git"
    else
        status_console "ALERTA" "$conf NÃO bloqueia .git"
        SITES_SEM_GIT+=("$conf")
   
