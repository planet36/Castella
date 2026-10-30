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
H4sIAAAAAAACA3VSsW7bMBDd+RXXyYth71mKZkhhtEEGG+0Y0NLJJETxBN7RqvL1fVQLJEsADSLf
8b137y6YzfpwPGqcZpWsh8HnXqZDJ9NxiWM8nplfn9fXX6zm3FkmpokzhZqNBimksxRzLxa46Pvt
INK7S2CSnFayEPONTrtpK2j/qHEnJZ9Jqg3RUOKNksiodMPbA6QYSivdobsnfT+4Z98zDUUmKuwT
yktMyVMXGvjEnJqeki7sjcuemjXeKWWhKxuuHMQy+QoAbjo6lagBEg37L7wxwNKedrZ4bdqdh/RK
fOfcOgB7eaC7n+ZYmK4A0a4yLSEak6Y4zy0RD9Cna8zivg0ldhDm3Pt8g6eeCoIRSH4v8e0NQV1B
SjX3XBq9u9RiiXVHmbtR90jwzujXmh0NoHaPoDGSgWaElniPvBuYt5M7WStLCUGpQeZS1oZuygJP
pDVaq8KwWfEWjSBTBWMhW+TzGXwAwPszjtsxiR/Q9FeiJykTF3id2140iZbiNuS2M2PcbHbB12Hg
iorHauTpVngNggBoqHBQ/3Av7rfU1CMafJvaWSixYaBz4bnla1vwvdwU6A8sQ/O+reHkrdt2r0v/
0E8begk0J7SOCBfJO6NV6seCL+4vIzQDPSkDAAA=
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
