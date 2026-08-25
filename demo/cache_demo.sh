#!/usr/bin/env bash
# Transparent MySQL query cache -- end-to-end demo.
#
#   docker compose exec bpf demo/cache_demo.sh
#
# Shows an expensive query, issued over TLS by an unmodified client, being
# served from Valkey on the second run. The application is not recompiled,
# reconfigured, or told the cache exists; no proxy sits in the path and no
# certificates are involved.
set -euo pipefail

cd "$(dirname "$0")/.."

MYSQL_HOST=${MYSQL_HOST:-mysql}
MYSQL_USER=${MYSQL_USER:-app}
MYSQL_PASSWORD=${MYSQL_PASSWORD:-apppw}
MYSQL_DB=${MYSQL_DB:-shop}
VALKEY_HOST=${VALKEY_HOST:-valkey}

LIB=build/libqcache.so
LIST=config/cache.list

# Deliberately expensive: SLEEP(1.5) per matching row, so the difference
# between "asked the database" and "served from cache" is unmistakable rather
# than a few milliseconds of noise.
Q="SELECT sku, name, price FROM products WHERE category = 'tools' AND SLEEP(1.5) = 0"

if [[ ! -f $LIB ]]; then
    echo "$LIB missing -- run 'make' first" >&2
    exit 1
fi

export QCACHE_LIST=$LIST
export QCACHE_VALKEY_HOST=$VALKEY_HOST
export QCACHE_TTL=${QCACHE_TTL:-120}

rule() { printf '%.0s-' {1..64}; echo; }

# Run the query and report wall-clock milliseconds.
timed() {
    local preload=$1 label=$2 start end
    start=$(date +%s%N)
    if [[ $preload == "yes" ]]; then
        LD_PRELOAD=$PWD/$LIB \
            mysql -h "$MYSQL_HOST" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" \
                  --ssl --ssl-verify-server-cert=0 "$MYSQL_DB" \
                  -e "$Q" >/tmp/qcache_out.txt 2>/dev/null
    else
        mysql -h "$MYSQL_HOST" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" \
              --ssl --ssl-verify-server-cert=0 "$MYSQL_DB" \
              -e "$Q" >/tmp/qcache_out.txt 2>/dev/null
    fi
    end=$(date +%s%N)
    printf '  %-34s %6d ms   (%d rows)\n' \
        "$label" $(( (end - start) / 1000000 )) $(( $(wc -l < /tmp/qcache_out.txt) - 1 ))
}

echo
rule
echo " Transparent MySQL query cache"
rule
echo
echo " Query (over TLS, unmodified client):"
echo "   $Q"
echo
echo " Cacheable statements: $LIST"
echo

redis-cli -h "$VALKEY_HOST" FLUSHALL >/dev/null
echo " Valkey flushed -- starting cold."
echo
rule
echo " 1. No cache at all (baseline)"
rule
timed no "straight to MySQL"

echo
rule
echo " 2. Cache enabled, cold -- must ask MySQL, then stores the answer"
rule
timed yes "cache MISS"

echo
rule
echo " 3. Cache warm -- MySQL is never contacted"
rule
timed yes "cache HIT"
timed yes "cache HIT"

echo
rule
echo " 4. Same cache, a different client and language"
rule
cat > /tmp/qcache_py_demo.py <<PYEOF
import pymysql, ssl, time
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
conn = pymysql.connect(host="$MYSQL_HOST", user="$MYSQL_USER",
                       password="$MYSQL_PASSWORD", database="$MYSQL_DB", ssl=ctx)
cur = conn.cursor()
t = time.time()
cur.execute("""$Q""")
rows = cur.fetchall()
print("  %-34s %6d ms   (%d rows)" % ("PyMySQL, cache HIT",
                                      int((time.time() - t) * 1000), len(rows)))
PYEOF
LD_PRELOAD=$PWD/$LIB python3 /tmp/qcache_py_demo.py

echo
rule
echo " 5. Correctness: results are byte-identical"
rule
LD_PRELOAD=$PWD/$LIB \
    mysql -h "$MYSQL_HOST" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" \
          --ssl --ssl-verify-server-cert=0 "$MYSQL_DB" -e "$Q" >/tmp/qcache_cached.txt 2>/dev/null
redis-cli -h "$VALKEY_HOST" FLUSHALL >/dev/null
QCACHE_DISABLE=1 \
    mysql -h "$MYSQL_HOST" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" \
          --ssl --ssl-verify-server-cert=0 "$MYSQL_DB" -e "$Q" >/tmp/qcache_live.txt 2>/dev/null
if diff -q /tmp/qcache_cached.txt /tmp/qcache_live.txt >/dev/null; then
    echo "  cached output == live output   OK"
else
    echo "  MISMATCH between cached and live output:"
    diff /tmp/qcache_live.txt /tmp/qcache_cached.txt || true
fi

echo
rule
echo " What just happened"
rule
cat <<'EOF'
  The client was never modified. It opened a normal TLS connection to
  MySQL and issued a normal query.

  The cache sits above TLS, on the plaintext side of the client's own
  SSL_write/SSL_read calls -- so there is no proxy in the path, no
  man-in-the-middle certificate, and nothing that needs its own network
  route to the database.

  On a hit the query is never transmitted: it is suppressed at SSL_write,
  the client's read() is told to retry, and the cached response is handed
  back through SSL_read with its packet sequence ids rewritten to match
  where this particular connection happens to be.
EOF
echo
