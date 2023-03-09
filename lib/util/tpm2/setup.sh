#!/bin/bash

export TPM2TOOLS_TCTI=tabrmd

full_path=$0
path=${full_path%/*}

tpm2_createek -c $path/../../../demo/credentials/ek.handle

tpm2_createak -C $path/../../../demo/credentials/ek.handle -c $path/../../../demo/credentials/ak.ctx -u $path/../../../demo/credentials/akpub.pem -f pem -p maatpass
