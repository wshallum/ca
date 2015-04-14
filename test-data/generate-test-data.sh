#!/bin/sh

openssl genrsa -out key12.pem 2048
openssl genrsa -out key3.pem 2048

openssl req -new -key key12.pem -keyform pem -subj "/C=ID/O=Test/OU=EDP/CN=Subject 1" -out request1.csr.der -outform der
openssl req -new -key key12.pem -keyform pem -subj "/C=ID/O=Test/OU=EDP/CN=Subject 2" -out request2.csr.der -outform der

cat > keyusage.cnf <<EOF
[req]
distinguished_name=req_dn
req_extensions=req_extensions
[req_dn]
[extensions]
keyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment
subjectAltName=email:test@example.com
EOF

openssl req -new -key key3.pem -keyform pem -config keyusage.cnf -reqexts extensions -subj "/C=ID/O=Test/OU=EDP/CN=Subject 3" -out request3.csr.der -outform der
