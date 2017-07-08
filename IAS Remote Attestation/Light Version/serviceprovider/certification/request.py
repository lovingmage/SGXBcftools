import requests
r = requests.get('https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v1/sigrl/00000689', cert=('client.crt', 'client.key'))
print r.status_code
print r.headers