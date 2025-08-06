import os
import time
import httpx
import jwt  # Make sure to import the jwt library

# --- Configuration ---
OKTA_DOMAIN = os.getenv("OKTA_DOMAIN")
CLIENT_ID = os.getenv("OKTA_CLIENT_ID")
SCOPE = os.getenv("OKTA_SCOPES") 

# Path to the private key you generated earlier
# For security, you can also load the key content from an env var
PRIVATE_KEY_PATH = "private.pem"


def get_okta_token():
    """
    Generates a client assertion JWT and exchanges it for an Okta access token.
    """
    token_url = f"{OKTA_DOMAIN}/oauth2/v1/token"
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
        print(token_url, headers, data)
        print("Sending token request...")
        resp = httpx.post(token_url, headers=headers, data=data, timeout=10.0)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as exc:
        print("Token request failed!")
        print("Status:", exc.response.status_code)
        print("Response headers:", exc.response.headers)
        print("Response body:", exc.response.text)
        raise

def list_users(access_token):
    """Fetches a list of users from the Okta org using an access token."""
    print("\nAttempting to fetch users...")

    # The endpoint for listing users in the Okta API
    users_url = f"{OKTA_DOMAIN}/api/v1/users"

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}"  # Use the token here
    }

    try:
        resp = httpx.get(users_url, headers=headers, timeout=10.0)
        resp.raise_for_status()  # Will raise an exception for 4xx/5xx responses
        return resp.json()
    except httpx.HTTPStatusError as exc:
        print(f"Failed to fetch users! Status: {exc.response.status_code}")
        print(f"Response body: {exc.response.text}")
        raise

# def list_applications(access_token):
#     """Fetches a list of applications from the Okta org using an access token."""
#     print("\nAttempting to fetch applications...")
#
#     # The endpoint for listing applications in the Okta API
#     apps_url = f"https://{OKTA_DOMAIN}/api/v1/apps"
#
#     headers = {
#         "Accept": "application/json",
#         "Authorization": f"Bearer {access_token}"  # Use the token here
#     }
#
#     try:
#         resp = httpx.get(apps_url, headers=headers, timeout=10.0)
#         resp.raise_for_status()  # Will raise an exception for 4xx/5xx responses
#         return resp.json()
#     except httpx.HTTPStatusError as exc:
#         print(f"Failed to fetch applications! Status: {exc.response.status_code}")
#         print(f"Response body: {exc.response.text}")
#         raise
# def create_user(access_token, user_profile):
#     """Creates a new user in Okta and activates them."""
#     print(f"\nAttempting to create user: {user_profile['profile']['login']}")
#     # The `?activate=true` query parameter creates and activates the user in one step
#     create_user_url = f"{OKTA_DOMAIN}/api/v1/users?activate=true"
#     headers = {
#         "Accept": "application/json",
#         "Content-Type": "application/json",
#         "Authorization": f"Bearer {access_token}"
#     }
#     try:
#         # For POST/PUT requests, use the `json` parameter in httpx
#         resp = httpx.post(create_user_url, headers=headers, json=user_profile)
#         resp.raise_for_status()
#         print("✅ User created successfully!")
#         return resp.json()
#     except httpx.HTTPStatusError as exc:
#         print(f"Failed to create user! Status: {exc.response.status_code}")
#         print(f"Response body: {exc.response.text}")
#         raise

# Add these functions to your existing script

def list_groups(access_token):
    """Fetches a list of groups from the Okta org."""
    print("\nAttempting to fetch groups...")
    groups_url = f"{OKTA_DOMAIN}/api/v1/groups"
    headers = { "Accept": "application/json", "Authorization": f"Bearer {access_token}" }
    try:
        resp = httpx.get(groups_url, headers=headers)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as exc:
        print(f"Failed to fetch groups! Status: {exc.response.status_code}")
        print(f"Response body: {exc.response.text}")
        raise

# def list_logs(access_token):
#     """Fetches system log events from the Okta org."""
#     print("\nAttempting to fetch system logs...")
#     # Fetch the 10 most recent log events
#     logs_url = f"{OKTA_DOMAIN}/api/v1/logs?limit=10"
#     headers = { "Accept": "application/json", "Authorization": f"Bearer {access_token}" }
#     try:
#         resp = httpx.get(logs_url, headers=headers)
#         resp.raise_for_status()
#         return resp.json()
#     except httpx.HTTPStatusError as exc:
#         print(f"Failed to fetch logs! Status: {exc.response.status_code}")
#         print(f"Response body: {exc.response.text}")
#         raise

def _create_user(access_token, user_profile):
    """Creates a new user in Okta and activates them."""
    print(f"\nAttempting to create user: {user_profile['profile']['login']}")
    # The `?activate=true` query parameter creates and activates the user in one step
    create_user_url = f"{OKTA_DOMAIN}/api/v1/users?activate=true"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }
    try:
        # For POST/PUT requests, use the `json` parameter in httpx
        resp = httpx.post(create_user_url, headers=headers, json=user_profile)
        resp.raise_for_status()
        print("✅ User created successfully!")
        return resp.json()
    except httpx.HTTPStatusError as exc:
        print(f"Failed to create user! Status: {exc.response.status_code}")
        print(f"Response body: {exc.response.text}")
        raise

def main():
    try:
        token_data = get_okta_token()
        access_token = token_data.get("access_token")

        if not access_token:
            print("Failed to get access token.")
            return

        print(access_token)

        # --- Perform READ operations ---
        # users = list_users(access_token)
        # print(f"\n✅ Found {len(users)} users in your org.")
        #
        # groups = list_groups(access_token)
        # print(f"\n✅ Found {len(groups)} groups in your org.")

        # logs = list_logs(access_token)
        # print(f"\n✅ Fetched {len(logs)} recent log events.")

        # --- Perform a WRITE operation ---
        new_user_data = {
            "profile": {
                "firstName": "Test",
                "lastName": "User",
                "email": f"test.user.{int(time.time())}@example.com",
                "login": f"test.user.{int(time.time())}@example.com"
            }
            # Okta will ask the user to set a password upon first login
        }
        created_user = _create_user(access_token, new_user_data)
        print(f"New user ID: {created_user.get('id')}")

    except Exception as e:
        print(f"\nAn error occurred: {e}")


if __name__ == "__main__":
    main()