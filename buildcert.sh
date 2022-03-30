#! /bin/bash

SUBJECT_ALT_NAME="URI:urn://policynetiot.com/${AE_ID},URI:urn:api:${APP_ID}"

SERIAL=2

LOG_LEVEL=-verbose

OUT_CERT="$1"

if [ -z "$OUT_CERT" ]; then
	OUT_CERT=csr.pem
fi

OUT_KEY="${OUT_CERT%.*}_key.pem"

openssl req \
	-new \
	-subj "/CN=${AE_ID}" \
	-subject \
	-pkeyopt ec_paramgen_curve:prime256v1 \
	-newkey ec -keyout "${OUT_KEY}" \
	-addext "subjectAltName=${SUBJECT_ALT_NAME}" \
	-addext "extendedKeyUsage=serverAuth,clientAuth,codeSigning" \
	-addext "keyUsage = digitalSignature,keyEncipherment" \
	-days $(( 10 * 365 )) \
	-set_serial "${SERIAL}" \
	${LOG_LEVEL} \
	-out "${OUT_CERT}"
