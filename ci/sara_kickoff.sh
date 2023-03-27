#! /bin/bash

# Kick off saracode

git archive --format=tar --prefix=maat/ HEAD | gzip -c > maat.tar.gz
HDR="X-Auth-Token: ${SARACODE_TOKEN}"
BUILD_ID=$(curl -s -k -F tarball=@maat.tar.gz -F build_name=$(git rev-parse HEAD) -X POST -H "${HDR}" ${SARACODE_ROOT}/analyze/58)
echo "${BUILD_ID}" | grep -qv '^[[:digit:]]*$' && (echo "Failed to create build: ${BUILD_ID}" ; exit 1) || /bin/true
echo BUILD_ID=${BUILD_ID} | tee saracode_build_id
