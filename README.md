## Usage

    APP_ID=${APP_ID_MATCHING_CREDENTIAL} AE_ID=${AE_ID_FROM_REGISTRATION} ./buildcert.sh

This will create csr.pem and key.pem

## Start to end code-signing key acquisition

1. Generate application credential in "System Settings" "AE Registration Credentials" tab
    a. Store the App-ID and resulting credential token
2. Register using https://github.com/droberts-aetheros/sdk-python
    a. Create and enter python3 virtualenvironment
    b. Install sdk-python with `./setup.py install`
    c. Run `python4 -m aosm2m -c ${IN_CSE_ADDRESS_WITH_PORT} -a ${APP_ID} --credential ${CREDENTIAL_TOKEN} --register`
    d. Store "token" returned on stdout
    e. Store "aei" value returned on stdout, this is the AE_ID
3. Generate a signing key and certificate signing request
    a. `APP_ID=${APP_ID_FROM_STEP_1_A} AE_ID=${AE_ID_FROM_STEP_2_D} ./buildcert.sh`
    b. By default this will create csr.pem and key.pem
4. Install python cryptography package `pip install cryptography`
5. Perform certificate signing request
    a. `./perform_csr.py --ae-id ${AE_ID_FROM_STEP_2_D} --token ${TOKEN_FROM_STEP_2_C} --csr csr.pem --cert-out cert.pem --ra ${RA_ADDRESS}`
    b. Store "token" returned on stdout
6. Use key.pem and cert.pem for code signing
