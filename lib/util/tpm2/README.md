# Using TPM2.0

## tpm2_tools commads
* Running `make check` when TPM2.0 is enabled will run two commands from `tpm2_tools` to generate files that are required for the unit tests:
  - `tpm2_createek` will generate an endorsement key and will save the EK to `../../../demo/credentials/ek.handle`. This file is needed for `tpm2_createak`.
  - `tpm2_createak` will generate an attestation key and will save the object context of the AK to `../../../demo/credentials/ak.ctx` and the public portion of the AK to `../../../demo/credentials/akpub.pem`. The AK context file is needed for signing with TPM2.0 (`tools/sign.c`) and the AK public key is needed for verifying signatures with TPM2.0 (`tools/checkquote.c`).
* If you wish to generate these files without `make check` (for example, using them with the demos in `../../../documentation/source/basic_tutorial.txt`), run the following commands:
    - `export TPM2TOOLS_TCTI=tabrmd`
    - `tpm2_createek -c ../../../demo/credentials/ek.handle`
    - `tpm2_createak -C ../../../demo/credentials/ek.handle -c ../../../demo/credentials/ak.ctx -u ../../../demo/credentials/akpub.pem -f pem -p maatpass`
