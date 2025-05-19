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

# (aqui vai todo o seu código de verificação... 
# como os checks das versões, usuários, ssh, firewall, etc — omitidos para foco no final)

# ----------------------------------------------------
# Exemplo parte crítica do seu último trecho (completo e fechado):

# 19. Verificar bloqueio .git e server_tokens em nginx

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

# Verificar se nginx.conf tem server_tokens off
if grep -q -E '^\s*server_tokens\s+off;' /etc/nginx/nginx.conf; then
    status_console "OK" "server_tokens está OFF no /etc/nginx/nginx.conf"
else
    status_console "ALERTA" "server_tokens NÃO está OFF no /etc/nginx/nginx.conf"
    NGINX_SEM_SERVER_TOKENS+=("/etc/nginx/nginx.conf")
fi

# Se estiver no modo update, aplicar correções para .git e server_tokens
if [ "$UPDATE_MODE" -eq 1 ]; then
    for conf in "${SITES_SEM_GIT[@]}"; do
        echo "Adicionando bloqueio .git em $conf"
        # Inserir bloco de localização para bloquear .git, exemplo básico
        if ! grep -q 'location ~ /\.git' "$conf"; then
            echo -e "\n# Bloqueio acesso .git\nlocation ~ /\.git {\n    deny all;\n}\n" >> "$conf"
            status_console "OK" "Bloqueio .git adicionado em $conf"
        else
            status_console "OK" "Bloqueio .git já presente em $conf"
        fi
    done

    # Adicionar server_tokens off em nginx.conf se não existir
    if [ ${#NGINX_SEM_SERVER_TOKENS[@]} -ne 0 ]; then
        echo "Adicionando 'server_tokens off;' em /etc/nginx/nginx.conf"
        # Coloca dentro do bloco http { ... }
        sed -i '/http {/a \    server_tokens off;' /etc/nginx/nginx.conf
        status_console "OK" "'server_tokens off;' adicionado em /etc/nginx/nginx.conf"
    fi

    echo "Recarregando nginx para aplicar alterações..."
    nginx -t && systemctl reload nginx && status_console "OK" "Nginx recarregado com sucesso" || status_console "ALERTA" "Falha ao recarregar nginx"
fi

echo "====== 🚨 AUDITORIA DE SEGURANÇA - FIM ======"

# Enviar log para termbin
TERMBIN_URL=$(curl -s --upload-file "$LOGFILE" https://termbin.com)
if [[ $TERMBIN_URL == http* ]]; then
    echo "Relatório enviado para: $TERMBIN_URL"
else
    echo "Falha ao enviar relatório para termbin"
fi
