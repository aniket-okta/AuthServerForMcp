import os
import time
import httpx
import jwt  # Make sure to import the jwt library

# --- Configuration ---
OKTA_DOMAIN = os.getenv("OKTA_DOMAIN")
CLIENT_ID = os.getenv("OKTA_CLIENT_ID")
SCOPE = os.getenv("OKTA_SCOPES")  # e.g., "api.read api.write"

# Path to the private key you generated earlier
# For security, you can also load the key content from an env var
PRIVATE_KEY_PATH = "private.pem"


def get_okta_token():
    """
    Generates a client assertion JWT and exchanges it for an Okta access token.
    """
    token_url = f"https://{OKTA_DOMAIN}/oauth2/v1/token"

    # 1. Load your private key
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        private_key = f.read()

    # 2. Prepare the claims for the JWT
    headers = {
        "alg": "RS256",
        # Find the 'kid' in your Okta application's public key settings after adding it.
        # You can hardcode it or get it from an environment variable.
        "kid": os.getenv("OKTA_KEY_ID")
    }

    payload = {
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "aud": token_url,
        "iat": int(time.time()),
        "exp": int(time.time()) + 300  # Expiration time (5 minutes from now)
    }

    # 3. Create the signed client assertion JWT
    client_assertion = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers=headers
    )

    # 4. Make the token request using the JWT
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "client_credentials",
        "scope": SCOPE,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion,
    }

    try:
        resp = httpx.post(token_url, headers=headers, data=data, timeout=10.0)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as exc:
        print("Token request failed!")
        print("Status:", exc.response.status_code)
        print("Response headers:", exc.response.headers)
        print("Response body:", exc.response.text)
        raise


def main():
    try:
        token_data = get_okta_token()
        access_token = token_data.get("access_token")
        expires_in = token_data.get("expires_in")
        scope = token_data.get("scope")
        print("✅ Successfully retrieved token!")
        print(f"Access Token: {access_token}")  # Print first 20 chars for brevity
        print(f"Expires in: {expires_in} seconds; Scopes: {scope}")
    except Exception as e:
        print(f"\nAn error occurred: {e}")


if __name__ == "__main__":
    # Ensure your environment variables are set
    # export OKTA_DOMAIN="your-okta-domain.okta.com"
    # export OKTA_CLIENT_ID="your-client-id"
    # export OKTA_SCOPES="your_scopes"
    # export OKTA_KEY_ID="your-key-id-from-okta"
    main()