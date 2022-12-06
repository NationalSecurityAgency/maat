#!/bin/bash
#
# Generate a new certificate using certtool.
# Run in this directory.  Provide unique id ('client1') as argument.
# Note that the id must be 'ca' in order to be usable with gen-new-cert.sh
#
# The password protection that can be enabled for the resulting
# private key is known to work with GNUTLS versions at or
# more recent than 3.5.18, although will likely work for some versions
# earlier than that.
#
# If your version of GNUTLS is older, and the certificate creation
# fails when you specify a password for the private key, it may be that your
# version of GNUTLS does not recognize the GNUTLS_PIN environment variable,
# in which case remove the line that declares that variable, and add
# '--password $2' to the certtool call to create the certificate
#

if [[ $# -lt 1 ]] || [[ $# -gt 2 ]]; then
    echo "Usage: $0 <cert_name> [private key password]"
    exit 1
fi

# Generate a new private key
echo "Generating Template.."
cp maat-ca-template.cfg $1.cfg
echo "cn=\"$1\"" >> $1.cfg

echo "Generating new private key..."
if [ $# -eq 1 ]; then
    certtool --generate-privkey --outfile $1.key --rsa
else
    certtool --generate-privkey --outfile $1.key --rsa --password $2

    export GNUTLS_PIN=$2
fi

echo "Creating Certificate..."
# Generate a certificate from the private key
certtool --generate-self-signed --load-privkey $1.key \
	 --outfile $1.pem --template $1.cfg

echo "Cert info"
certtool --certificate-info --infile $1.pem

echo "Certificate $1.pem created with fingerprint:"
certtool --fingerprint --infile $1.pem
openssl x509 -fingerprint -in $1.pem -noout | cut -f 2 -d '='

