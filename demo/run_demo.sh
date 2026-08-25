#!/usr/bin/env bash
# End-to-end demo: capture live MySQL queries via agent and answer from Valkey.
#
# Run inside the bpf container:  docker compose exec bpf demo/run_demo.sh
set -euo pipefail

cd "$(dirname "$0")/.."

MYSQL_HOST=${MYSQL_HOST:-mysql}
MYSQL_USER=${MYSQL_USER:-app}
MYSQL_PASSWORD=${MYSQL_PASSWORD:-apppw}
MYSQL_DB=${MYSQL_DB:-shop}

if [[ ! -x build/agent ]]; then
    echo "build/agent missing -- run 'make' first" >&2
    exit 1
fi

# --skip-ssl matters: TLS would encrypt the payload before write(2) and the
# tracer would have nothing to pattern-match.
mysql_run() {
    mysql -h "$MYSQL_HOST" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" --skip-ssl \
          "$MYSQL_DB" -e "$1" >/dev/null 2>&1 || true
}

echo "==> refreshing Valkey mirror"
python3 demo/mirror.py

echo
echo "==> starting agent -> translator pipeline"
# Unbuffered so lines appear as the statements are captured.
stdbuf -oL ./build/agent 2>/dev/null \
    | stdbuf -oL python3 translator/bridge.py --execute --quiet-errors &
PIPELINE=$!
# shellcheck disable=SC2064
trap "kill $PIPELINE 2>/dev/null || true" EXIT

sleep 2

echo "==> issuing MySQL queries (these are real queries against the real server)"
mysql_run "SELECT name, price FROM products WHERE category = 'tools' AND price < 30"
mysql_run "SELECT * FROM products WHERE brand IN ('acme','globex') AND rating >= 4.5 ORDER BY price DESC LIMIT 5"
mysql_run "SELECT COUNT(*) FROM orders WHERE status = 'shipped'"
mysql_run "SELECT * FROM products WHERE price BETWEEN 10 AND 20 OR stock = 0"
mysql_run "SELECT sku FROM products WHERE sku LIKE 'SKU-00%'"
mysql_run "SELECT * FROM orders WHERE total >= 100 AND status != 'cancelled'"
mysql_run "SELECT * FROM products WHERE name = 'Cordless Drill'"
# Deliberately out of scope: shows the bridge skipping what it cannot translate.
mysql_run "SELECT p.name, o.qty FROM products p JOIN orders o ON p.sku = o.sku"

sleep 2
echo
echo "==> done"
