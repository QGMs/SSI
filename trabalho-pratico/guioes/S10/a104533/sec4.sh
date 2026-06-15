#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

cat > "$SCRIPT_DIR/task7_example32b_apache.conf" <<'EOF'
# example32a: sem CSP
<VirtualHost *:80>
    DocumentRoot /var/www/csp
    ServerName www.example32a.com
    DirectoryIndex index.html
</VirtualHost>

# example32b: permitir scripts de self, example60 e example70
<VirtualHost *:80>
    DocumentRoot /var/www/csp
    ServerName www.example32b.com
    DirectoryIndex index.html
    Header set Content-Security-Policy " \
             default-src 'self'; \
             script-src 'self' *.example60.com *.example70.com \
           "
</VirtualHost>

# example32c: CSP definida na aplicacao PHP
<VirtualHost *:80>
    DocumentRoot /var/www/csp
    ServerName www.example32c.com
    DirectoryIndex phpindex.php
</VirtualHost>

<VirtualHost *:80>
    DocumentRoot /var/www/csp
    ServerName www.example60.com
</VirtualHost>

<VirtualHost *:80>
    DocumentRoot /var/www/csp
    ServerName www.example70.com
</VirtualHost>
EOF

cat > "$SCRIPT_DIR/task7_example32c_phpindex.php" <<'EOF'
<?php
  $cspheader = "Content-Security-Policy:".
               "default-src 'self';".
               "script-src 'self' 'nonce-111-111-111' 'nonce-222-222-222' *.example60.com *.example70.com";
  header($cspheader);
?>

<?php include 'index.html'; ?>
EOF

cat > "$SCRIPT_DIR/task7_expected_behaviour.txt" <<'EOF'
Task 7 - Comportamento esperado

example32a:
- Areas 1, 2, 3, 4, 5 e 6 mostram OK
- O botao onclick executa JavaScript

example32b original:
- Areas 4 e 6 mostram OK
- Areas 1, 2, 3 e 5 falham
- O botao onclick e bloqueado

example32c original:
- Areas 1, 4 e 6 mostram OK
- Areas 2, 3 e 5 falham
- O botao onclick e bloqueado

Depois das alteracoes deste script:

example32b modificado:
- Areas 4, 5 e 6 mostram OK

example32c modificado:
- Areas 1, 2, 4, 5 e 6 mostram OK
- Area 3 continua bloqueada
- O botao onclick continua bloqueado
EOF

printf 'Gerados: task7_example32b_apache.conf, task7_example32c_phpindex.php, task7_expected_behaviour.txt\n'

# Testes/uso:
# - Substituir a config Apache de example32b por task7_example32b_apache.conf
# - Substituir phpindex.php de example32c por task7_example32c_phpindex.php
# - Reiniciar o ambiente Docker e observar as Areas permitidas/bloqueadas
