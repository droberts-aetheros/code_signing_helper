#! /usr/bin/env python3

import argparse
import base64
import requests

from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

import json

import sys

oid_name_map = {
    "2.5.4.3": "CN",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.6": "C",
    "2.5.4.9": "STREET",
    "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID",
}

def generate_csr_request(ae_id, token_id, xcsr):
    device = {"wanaddr": ae_id, "tokenid": token_id}
    return {"pnm2m:signreq": {"device": device, "xcsr": xcsr}}

def generate_csr_confirmation_request(resp):
    iresp = resp['pnm2m:signresp']
    cert_bytes = iresp['clientcert'].encode('latin-1')
    txnid = iresp['confirmtxnid']

    cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

    certhash = cert.fingerprint(SHA256())
    certhash = base64.b64encode(certhash).decode('latin-1')
    serial = cert.serial_number
    issuer = cert.issuer
    certid = {"serial": serial, "issuer": rfc4514(issuer)}
    return {"pnm2m:confirmreq": {"certhash": certhash, "certid": certid, "txnid": txnid}}

def rfc4514(name):
    items = []
    for n in name.rdns:
        attr, = n

        rdname = oid_name_map[attr.oid.dotted_string]

        items.append(f"{rdname}={attr.value}")

    return ", ".join(items)

def perform_csr(args):
    ra = args.ra

    cert_out = args.cert_out

    ca_out = args.ca_out if hasattr(args, 'ca_out') else None

    with open(args.csr) as f:
        xcsr = f.read()

    request = generate_csr_request(args.ae_id, args.token, xcsr)

    response = requests.post(f"{ra}/CertificateSigning", data=json.dumps(request), verify=not args.insecure)

    json_resp = json.loads(response.text)

    with open(cert_out, "w") as f:
        f.write(json_resp['pnm2m:signresp']['clientcert'])
    
    request = generate_csr_confirmation_request(json_resp)

    response = requests.post(f"{ra}/CertificateConfirm", data=json.dumps(request), verify=not args.insecure)

    json_resp = json.loads(response.text)

    if ca_out is not None:
        with open(ca_out, "w") as f:
            f.write(json_resp['pnm2m:confirmresp']['cacertpem'])

    print(f"token = {json_resp['pnm2m:confirmresp']['newtokenid']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    #parser.add_argument("-", "--")
    parser.add_argument("--ae-id")
    parser.add_argument("--token")
    parser.add_argument("--csr")
    parser.add_argument("--ra")
    parser.add_argument("--ca-out")
    parser.add_argument("--cert-out")
    parser.add_argument("--insecure", default=False, action="store_true")
    parser.add_argument("-o", "--out")
    parser.add_argument("-C", "--ca", default=False, action="store_true")
    parser.add_argument("-c", "--cert", action="store_true", default=False)

    args = parser.parse_args()

    if hasattr(args, 'csr'):
        perform_csr(args)
    else:
        parser.print_help()
