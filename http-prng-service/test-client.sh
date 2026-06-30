#!/usr/bin/sh
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

BASE_URL='http://localhost'
PORT=8080

echo "# Send bytes to the service."

echo
echo "POST /absorb  # \"Lorem ipsum...\" (Content-Type: application/octet-stream)"
cat <<'EOT' | curl --fail --data-binary @- --header "Content-Type: application/octet-stream" "$BASE_URL:$PORT/absorb" || exit
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor
incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis
nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non
proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
https://www.lipsum.com/
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
curl --fail --show-error --silent "$BASE_URL:$PORT/squeeze" | basenc --wrap=0 --base58 || exit ; echo

sleep 4

echo
echo "GET /squeeze/  # The default value is used."
curl --fail --show-error --silent "$BASE_URL:$PORT/squeeze/" | basenc --wrap=0 --base58 || exit ; echo

sleep 4

echo
echo "GET /squeeze/0  # nothing (a.k.a. \"mute\" call)"
curl --fail --show-error --silent "$BASE_URL:$PORT/squeeze/0" | basenc --wrap=0 --base58 || exit ; echo

sleep 4

echo
echo "GET /squeeze/32"
curl --fail --show-error --silent "$BASE_URL:$PORT/squeeze/32" | basenc --wrap=0 --base58 || exit ; echo

sleep 4

echo
echo "GET /squeeze/asdf  # The default value is used."
curl --fail --show-error --silent "$BASE_URL:$PORT/squeeze/asdf" | basenc --wrap=0 --base58 || exit ; echo

sleep 4

echo
echo "GET /squeeze/999999  # The value is clamped by Castella."
curl --fail --show-error --silent "$BASE_URL:$PORT/squeeze/999999" | basenc --wrap=0 --base58 || exit ; echo
