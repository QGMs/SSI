#!/bin/bash
set -e

sign_cert() {
    local csr_file="$1"
    local crt_file="$2"

    if [ -f CA.srl ]; then
        openssl x509 -req -in "$csr_file" -CA CA.crt -CAkey CA.key -CAserial CA.srl -out "$crt_file" -days 365 -sha256
    else
        openssl x509 -req -in "$csr_file" -CA CA.crt -CAkey CA.key -CAcreateserial -out "$crt_file" -days 365 -sha256
    fi
}

openssl genrsa -out CA.key 2048
openssl genrsa -out Alice.key 2048
openssl genrsa -out Bob.key 2048

openssl req -x509 -new -nodes -key CA.key -sha256 -days 365 -out CA.crt -subj "/CN=CA"

openssl req -new -key Alice.key -out Alice.csr -subj "/CN=Alice"
sign_cert Alice.csr Alice.crt

openssl req -new -key Bob.key -out Bob.csr -subj "/CN=Bob"
sign_cert Bob.csr Bob.crt
