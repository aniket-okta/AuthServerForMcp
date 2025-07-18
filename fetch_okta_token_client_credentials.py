import os
import requests
from requests.auth import HTTPBasicAuth

# Read configuration from environment variables
OKTA_ORG_URL = os.getenv('OKTA_ORG_URL')
CLIENT_ID = os.getenv('OKTA_CLIENT_ID')
CLIENT_SECRET = os.getenv('OKTA_CLIENT_SECRET')
SCOPE = os.getenv('OKTA_SCOPE', 'customScope')  # Default scope if not set

if not OKTA_ORG_URL or not CLIENT_ID or not CLIENT_SECRET:
    print("ERROR: Please set OKTA_ORG_URL, OKTA_CLIENT_ID, and OKTA_CLIENT_SECRET environment variables.")
    exit(1)

TOKEN_URL = f'{OKTA_ORG_URL}/oauth2/default/v1/token'

data = {
    'grant_type': 'client_credentials',
    'scope': SCOPE
}

try:
    response = requests.post(
        TOKEN_URL,
        data=data,
        auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    )
    if response.status_code == 200:
        token_info = response.json()
        print("Access Token:", token_info['access_token'])
    else:
        print("Failed to fetch token:", response.status_code, response.text)
except Exception as e:
    print("Exception occurred while fetching token:", str(e)) 