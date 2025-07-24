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
    # Inside the get_okta_token function, before the try block:
    print(f"Requesting token with scopes: {SCOPE}")
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


def list_applications(access_token):
    """Fetches a list of applications from the Okta org using an access token."""
    print("\nAttempting to fetch applications...")

    # The endpoint for listing applications in the Okta API
    apps_url = f"https://{OKTA_DOMAIN}/api/v1/apps"

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}"  # Use the token here
    }

    try:
        resp = httpx.get(apps_url, headers=headers, timeout=10.0)
        resp.raise_for_status()  # Will raise an exception for 4xx/5xx responses
        return resp.json()
    except httpx.HTTPStatusError as exc:
        print(f"Failed to fetch applications! Status: {exc.response.status_code}")
        print(f"Response body: {exc.response.text}")
        raise


def main():
    try:
        token_data = get_okta_token()
        access_token = token_data.get("access_token")

        # --- Add this line for debugging ---
        print("\n--- DECODING TOKEN ---")
        print(access_token)
        print("--- END TOKEN ---\n")

        print("✅ Successfully retrieved access token!")

        # Step 2: Use the token to get the list of apps
        if access_token:
            apps = list_applications(access_token)
            print("\n✅ Successfully retrieved applications in your org:")
            for app in apps:
                print(f"- Label: {app.get('label', 'N/A')}, ID: {app.get('id', 'N/A')}")

    except Exception as e:
        print(f"\nAn error occurred: {e}")


if __name__ == "__main__":
    main()