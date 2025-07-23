import os
import base64
import httpx

OKTA_DOMAIN = os.getenv("OKTA_DOMAIN")  # e.g. "dev-123456.okta.com"
CLIENT_ID = os.getenv("OKTA_CLIENT_ID")
CLIENT_SECRET = os.getenv("OKTA_CLIENT_SECRET")
SCOPE = os.getenv("OKTA_SCOPES")  # e.g. "api.read"

def get_okta_token():
    token_url = f"https://{OKTA_DOMAIN}/oauth2/v1/token"
    # Basic auth header with Base64-encoded client_id:client_secret
    creds = f"{CLIENT_ID}:{CLIENT_SECRET}"
    b64_creds = base64.b64encode(creds.encode()).decode()
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {b64_creds}",
    }
    data = {
        "grant_type": "client_credentials",
        "scope": SCOPE,
    }
    try:
        resp = httpx.post(token_url, headers=headers, data=data, timeout=10.0)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as exc:
        print("🛑 Token request failed!")
        print("Status:", exc.response.status_code)
        print("Response headers:", exc.response.headers)
        print("Response body:", exc.response.text)
        raise

def main():
    token_data = get_okta_token()
    access_token = token_data.get("access_token")
    expires_in = token_data.get("expires_in")
    scope = token_data.get("scope")
    print(f"Access Token: {access_token}")
    print(f"Expires in: {expires_in} seconds; Scopes: {scope}")

if __name__ == "__main__":
    main()
