openssl x509 -fingerprint -in $1 -noout | cut -f 2 -d '='
