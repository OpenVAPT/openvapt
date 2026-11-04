#!/bin/sh
# Tell IndexNow engines (Bing, Yandex, Naver, Seznam and others; Google does
# not take part) which openvapt.com pages changed, right after a deploy.
#
#   sh scripts/indexnow.sh dist/site                 # every URL in the sitemap
#   sh scripts/indexnow.sh dist/site https://openvapt.com/faq.html ...   # only these
#
# The key is read from site/indexnow-key.txt and must be served at
# https://openvapt.com/<key>.txt (site/static publishes it). It is not a
# secret: it lets anyone say "this page changed", nothing more. One POST per
# run, at most 10,000 URLs, over HTTPS with TLS 1.2 or newer, nothing else.
set -eu
DIR=${1:?built site dir}
shift || true
KEY=$(tr -d '[:space:]' < "$(dirname "$0")/../site/indexnow-key.txt")
case "$KEY" in *[!0-9a-f]*|'') echo "indexnow: bad key" >&2; exit 1;; esac
test -s "$DIR/$KEY.txt" || { echo "indexnow: $DIR/$KEY.txt missing (sitegen copies site/static)" >&2; exit 1; }
if [ "$#" -gt 0 ]; then
  URLS=$(printf '%s\n' "$@")
else
  URLS=$(sed -n 's|.*<loc>\(https://openvapt\.com/[^<]*\)</loc>.*|\1|p' "$DIR/sitemap.xml")
fi
N=$(printf '%s\n' "$URLS" | grep -c . || true)
[ "$N" -gt 0 ] || { echo "indexnow: no URLs" >&2; exit 1; }
[ "$N" -le 10000 ] || { echo "indexnow: $N URLs is over the 10,000 limit" >&2; exit 1; }
BODY=$(printf '%s\n' "$URLS" | grep . | awk -v key="$KEY" 'BEGIN{printf "{\"host\":\"openvapt.com\",\"key\":\"%s\",\"keyLocation\":\"https://openvapt.com/%s.txt\",\"urlList\":[", key, key}
  {gsub(/["\\]/, ""); printf "%s\"%s\"", (NR>1?",":""), $0} END{print "]}"}')
CODE=$(printf '%s' "$BODY" | curl -sS --proto '=https' --tlsv1.2 -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json; charset=utf-8' --data-binary @- https://api.indexnow.org/indexnow)
echo "indexnow: submitted $N URLs, HTTP $CODE (200 or 202 = accepted)"
case "$CODE" in 200|202) exit 0;; *) exit 1;; esac
