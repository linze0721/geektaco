#!/bin/sh
# geektaco v2 smoke test: threads, invites, admin, persistence.
# Exercises the real binary over real HTTP. No mocks.
set -e
cd "$(dirname "$0")"

PORT=8090
rm -f geektaco.db geektaco.inv geektaco.key

./geektaco > /tmp/gt.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
sleep 0.5

fail() { echo "FAIL: $1"; exit 1; }
has()  { echo "$2" | grep -qF "$1" || fail "$3"; }
hasnt(){ echo "$2" | grep -qF "$1" && fail "$3" || true; }
C()    { curl -s -m 5 "$@"; }
U="http://127.0.0.1:$PORT"

KEY=$(cat geektaco.key)
[ -n "$KEY" ] || fail "no admin key generated"

echo "== 1. threads =="
N=$(ls /proc/$SRV/task | wc -l)
[ "$N" = "4" ] || fail "expected 4 worker tasks, got $N"

echo "== 2. public index is readable without a token =="
R=$(C -i "$U/")
has "200 OK" "$R" "index not 200"
has "/join" "$R" "no link to join page"
hasnt "/admin" "$R" "admin panel advertised on a public page"

echo "== 3. posting without an invite is refused =="
R=$(C -i -X POST "$U/new" --data-urlencode 'a=x' --data-urlencode 't=x' --data-urlencode 'b=x')
has "403" "$R" "POST /new without invite should be 403"
CUR=$(python3 -c "
import struct;print(struct.unpack_from('<I',open('geektaco.db','rb').read(),12)[0])")
[ "$CUR" = "0" ] || fail "unauthorised POST advanced the cursor to $CUR"

echo "== 4. admin panel is invisible without the key =="
R=$(C -i "$U/admin")
has "404" "$R" "unauthenticated /admin must 404, not 403"

echo "== 5. admin panel with the key =="
R=$(C -i -b "ga=$KEY" "$U/admin")
has "200 OK" "$R" "admin panel not served with valid key"
has "/admin/inv" "$R" "no create-invite form"

echo "== 6. create an invite =="
C -o /dev/null -X POST -b "ga=$KEY" "$U/admin/inv"
CODE=$(python3 -c "
d=open('geektaco.inv','rb').read()
print(d[32:48].split(b'\0')[0].decode())")
[ ${#CODE} = 16 ] || fail "invite code is ${#CODE} chars, want 16"
echo "  code: $CODE"

echo "== 7. redeem it =="
R=$(C -i -X POST "$U/join" --data-urlencode "c=$CODE")
has "Set-Cookie" "$R" "join did not set a cookie"
has "HttpOnly" "$R" "cookie missing HttpOnly"
has "SameSite=Strict" "$R" "cookie missing SameSite=Strict"

echo "== 8. bogus code is rejected =="
R=$(C -i -X POST "$U/join" --data-urlencode 'c=0000000000000000')
hasnt "Set-Cookie" "$R" "bogus code got a cookie"

echo "== 9. posting as a member =="
C -o /dev/null -X POST -b "gt=$CODE" "$U/new" \
  --data-urlencode 'a=member' --data-urlencode 't=hello <world> & "friends"' \
  --data-urlencode 'b=line one
line two'
R=$(C "$U/")
has "/t/0" "$R" "thread not listed"
has "&lt;world&gt;" "$R" "title not escaped (XSS!)"
has "&amp;" "$R" "ampersand not escaped"

echo "== 10. authorship is recorded =="
INV=$(python3 -c "
import struct;print(struct.unpack_from('<i',open('geektaco.db','rb').read(),512+12)[0])")
[ "$INV" = "0" ] || fail "R_INVITE is $INV, expected 0"

echo "== 11. replies and the denormalised count =="
for i in 1 2 3; do
  C -o /dev/null -X POST -b "gt=$CODE" "$U/reply" \
    --data-urlencode 'p=0' --data-urlencode "a=r$i" --data-urlencode "b=reply $i"
done
NR=$(python3 -c "
import struct;print(struct.unpack_from('<I',open('geektaco.db','rb').read(),512+16)[0])")
[ "$NR" = "3" ] || fail "R_NREPLY is $NR, expected 3"
R=$(C "$U/t/0")
has "reply 3" "$R" "reply missing from thread page"

echo "== 12. XSS probe =="
C -o /dev/null -X POST -b "gt=$CODE" "$U/new" \
  --data-urlencode 'a=x' --data-urlencode 't=t' \
  --data-urlencode 'b=<script>alert(1)</script>'
R=$(C "$U/t/4")
hasnt "<script>alert" "$R" "raw <script> reached output (XSS!)"
has "&lt;script&gt;" "$R" "script tag not escaped"
# Markdown: the scheme allowlist is the only thing making links safe, and
# escape-before-markup is the only thing making the rest safe.
C -o /dev/null -X POST -b "gt=$CODE" "$U/new" \
  --data-urlencode 't=md' \
  --data-urlencode 'b=**b** `c` [ok](https://e.com) [no](javascript:alert(1))'
R=$(C "$U/t/5")
has "<strong>b</strong>" "$R" "markdown bold not rendered"
has "<code>c</code>" "$R" "markdown code not rendered"
has 'href="https://e.com"' "$R" "safe link not rendered"
echo "$R" | grep -qiE 'href="[^"]*javascript:' && fail "javascript: reached an href (XSS!)"
has "[no](javascript:" "$R" "rejected link should render literally"

echo "== 13. admin delete hides a post =="
C -o /dev/null -X POST -b "ga=$KEY" "$U/admin/del" --data-urlencode 'i=4'
R=$(C "$U/")
hasnt "/t/4" "$R" "deleted thread still listed"
R=$(C -b "ga=$KEY" "$U/admin")
has "deleted" "$R" "admin view should still show deleted records"

echo "== 14. revoke cuts off the member =="
C -o /dev/null -X POST -b "ga=$KEY" "$U/admin/rev" --data-urlencode 'i=0'
R=$(C -i -X POST -b "gt=$CODE" "$U/new" \
  --data-urlencode 'a=x' --data-urlencode 't=x' --data-urlencode 'b=x')
has "403" "$R" "revoked invite can still post"

echo "== 15. concurrency: 40 parallel posts, no lost or duplicated slot =="
C -o /dev/null -X POST -b "ga=$KEY" "$U/admin/inv"
CODE2=$(python3 -c "
d=open('geektaco.inv','rb').read()
print(d[64:80].split(b'\0')[0].decode())")
i=1
while [ $i -le 40 ]; do
  C -o /dev/null -X POST -b "gt=$CODE2" "$U/new" \
    --data-urlencode "a=u$i" --data-urlencode "t=T$i" --data-urlencode "b=B$i" &
  i=$((i+1))
done
sleep 4
python3 - <<'PY' || fail "allocator lost or duplicated a slot"
import struct
d = open('geektaco.db','rb').read()
cur = struct.unpack_from('<I', d, 12)[0]
seen = {}
for i in range(cur):
    o = (i+1)*512
    if struct.unpack_from('<I', d, o+4)[0] == 0: continue
    t = d[o+44:o+124].split(b'\0')[0].decode('utf8','replace')
    if t.startswith('T'):
        assert t not in seen, f"duplicate {t} at {seen.get(t)} and {i}"
        seen[t] = i
assert len(seen) == 40, f"only {len(seen)}/40 concurrent posts survived"
print(f"  OK cursor={cur}, 40 distinct concurrent records")
PY

echo "== 16. worker survives a client reset =="
python3 -c "
import socket
for _ in range(5):
    s=socket.create_connection(('127.0.0.1',$PORT)); s.sendall(b'GET / HTTP/1.0\r\n\r\n'); s.close()"
sleep 0.3
N=$(ls /proc/$SRV/task | wc -l)
[ "$N" = "4" ] || fail "a worker died: $N tasks left"

echo "== 17. malformed input does not kill the server =="
printf 'GARBAGE\r\n\r\n' | timeout 2 nc 127.0.0.1 $PORT >/dev/null 2>&1 || true
printf 'POST /new HTTP/1.0\r\nContent-Length: 99999\r\n\r\nshort' | timeout 2 nc 127.0.0.1 $PORT >/dev/null 2>&1 || true
C -o /dev/null "$U/t/99999999999999999999"
C -o /dev/null "$U/t/abc"
kill -0 $SRV 2>/dev/null || fail "server died on malformed input"

echo "== 18. pagination =="
# 45 records exist by now, of which 42 are roots: 25 on page 0, 17 on page 1.
N0=$(C "$U/" | grep -o 'href="/t/' | wc -l)
N1=$(C "$U/p/1" | grep -o 'href="/t/' | wc -l)
[ "$N0" = "25" ] || fail "page 0 shows $N0 threads, want 25"
echo "  page 0: $N0, page 1: $N1"
has "next" "$(C "$U/")" "page 0 missing the older link"
hasnt "prev" "$(C "$U/")" "page 0 must not offer a newer link"
has "prev" "$(C "$U/p/1")" "page 1 missing the newer link"
# A malformed page number is a bad URL, not silently page 0.
has "404" "$(C -i "$U/p/abc")" "/p/abc should 404"
has "404" "$(C -i "$U/t/0/abc")" "/t/0/abc should 404"
# The canonical first page and its explicit form agree.
[ "$(C "$U/t/0" | md5sum)" = "$(C "$U/t/0/0" | md5sum)" ] \
  || fail "/t/0 and /t/0/0 differ"

echo "== 19. persistence across restart =="
kill $SRV; wait $SRV 2>/dev/null || true
./geektaco > /tmp/gt2.log 2>&1 &
SRV=$!
sleep 0.5
# Record 0 is on a later index page now that 45 records exist, so check the
# thread page directly -- that is what "the data survived" actually means.
R=$(C "$U/t/0")
has "hello" "$R" "data lost across restart"
has "reply 3" "$R" "replies lost across restart"
[ "$(cat geektaco.key)" = "$KEY" ] || fail "admin key regenerated on restart"
grep -q "Admin key" /tmp/gt2.log && fail "key reprinted on restart" || true
R=$(C -i -b "ga=$KEY" "$U/admin")
has "200 OK" "$R" "admin key no longer works after restart"

echo
echo "ALL PASS  (binary $(stat -c%s geektaco) bytes, db $(du -k geektaco.db|cut -f1)K on disk)"
