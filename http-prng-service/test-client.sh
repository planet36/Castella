#!/usr/bin/sh
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# castella-svc must be running.

BASE_URL='http://localhost'
PORT=8080

echo "# Send bytes to the service."

echo
echo "POST /absorb  # base64-encoded gzipped data (Content-Type: application/octet-stream)"
cat <<'EOT' | curl --fail --data-binary @- --header "Content-Type: application/octet-stream" "$BASE_URL:$PORT/absorb" || exit
H4sIAAAAAAACA3VSsW7jMAzd9RW8KUuQ7F0O7dAiuBYdEtyNhWLTkRBZNEQqrvv19+Q7oF0KeLD0
qPceHxnMJr3b7zWOk0rW3eBzL+Ouk3E/x2vcH5nfXpa336zm3FFGppEzhZqNBimkkxRzrxa46Oft
INK7U2CSnBayEPOFDptxLWj/qHEHJZ9Jqg3RUOKNkshV6YK3O0gxlBa6QXdL+nlwL75nGoqMVNgn
lJeYkqcuNPCROTU9JZ3ZG5ctNWu8UcpCZzZcOYhl8hUA3HR0KFEDJBr2X3hlgKUtbWz22rQ7D+mF
+Ma5dQD2ckc3P06xMJ0Bol1lmkM0Jk1xmloiHqBP55jF3Q8ldhDm3Pt8gaeeCoIRSD6V+PGBoM4g
pZp7Lo3enWqxxLqhzN1Vt0jwxujXmh0NoHYPoDGSgSaElniLvBuY15M7WCtLCUGpQeZUloauygJP
pDVaq8KwWfEWjSBTBWMhm+X7GXwBwPscr+sxiR/Q9E+iRykjF3id2l40iZbiOuS2M9e42uyCr8PA
FRUP1cjTU+ElCAKgocJBfede3B+pqUc0+Fa1o1Biw0CnwlPL19bge7ko0F9YhuZ9XcPRW7fuXpf+
od829BpoSmgdEc6SN0aL1K8FP9xfIfBYICkDAAA=
EOT

sleep 4

echo
echo "POST /absorb  # nothing (a.k.a. \"blank\" call) (Content-Type: application/octet-stream)"
printf '' | curl --fail --data-binary @- --header "Content-Type: application/octet-stream" "$BASE_URL:$PORT/absorb" || exit

sleep 4

# "application/x-www-form-urlencoded" is the default Content-Type for POST, but it duplicates the `req.body` in `req.params`.
# Specify Content-Type "application/octet-stream" to prevent this.
echo
echo "POST /absorb  # /dev/urandom (Content-Type: application/octet-stream)"
head --bytes=32 /dev/urandom | curl --fail --data-binary @- --header "Content-Type: application/octet-stream" "$BASE_URL:$PORT/absorb" || exit

sleep 4

echo
echo "POST /absorb  # /dev/urandom (Content-Type: application/x-www-form-urlencoded)"
head --bytes=32 /dev/urandom | curl --fail --data-binary @- "$BASE_URL:$PORT/absorb" || exit

sleep 4

echo
echo "# Receive bytes from the service."

echo
echo "GET /squeeze  # The default value is used."
curl --fail --show-error --silent "$BASE_URL:$PORT/squeeze" | basenc --wrap=0 --base16 || exit ; echo

sleep 4

echo
echo "GET /squeeze/  # The default value is used."
curl --fail --show-error --silent "$BASE_URL:$PORT/squeeze/" | basenc --wrap=0 --base16 || exit ; echo

sleep 4

echo
echo "GET /squeeze/0  # nothing (a.k.a. \"mute\" call)"
curl --fail --show-error --silent "$BASE_URL:$PORT/squeeze/0" | basenc --wrap=0 --base16 || exit ; echo

sleep 4

echo
echo "GET /squeeze/32"
curl --fail --show-error --silent "$BASE_URL:$PORT/squeeze/32" | basenc --wrap=0 --base16 || exit ; echo

sleep 4

echo
echo "GET /squeeze/asdf  # The default value is used."
curl --fail --show-error --silent "$BASE_URL:$PORT/squeeze/asdf" | basenc --wrap=0 --base16 || exit ; echo

sleep 4

echo
echo "GET /squeeze/999999  # The value is clamped by Castella."
curl --fail --show-error --silent "$BASE_URL:$PORT/squeeze/999999" | basenc --wrap=0 --base16 || exit ; echo
