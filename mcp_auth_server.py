import os
import requests
import json
import time
import webbrowser
import sys


def get_okta_config():
    """Prompts the user for Okta configuration details."""
    print("--- Okta Configuration ---")
    org_url = input("Enter your Okta Org URL (e.g., https://dev-XXXXXXXX.okta.com): ").strip()
    client_id = input("Enter your Okta Client ID: ").strip()
    scopes = input("Enter Okta Scopes (default: openid profile email offline_access): ").strip()

    if not org_url:
        print("Okta Org URL cannot be empty. Exiting.")
        sys.exit(1)
    if not client_id:
        print("Okta Client ID cannot be empty. Exiting.")
        sys.exit(1)

    if not scopes:
        scopes = "openid profile email offline_access"  # Default scopes

    # Ensure the URL is properly formatted
    if not org_url.startswith("http://") and not org_url.startswith("https://"):
        org_url = "https://" + org_url

    print("\nConfiguration received:")
    print(f"  Org URL: {org_url}")
    print(f"  Client ID: {client_id}")
    print(f"  Scopes: {scopes}")

    return org_url, client_id, scopes


def initiate_device_authorization(okta_org_url, okta_client_id, okta_scopes):
    """
    Initiates the Okta Device Authorization flow and returns device data.
    """
    auth_url = f"{okta_org_url}/oauth2/v1/device/authorize"
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'client_id': okta_client_id,
        'scope': okta_scopes
    }

    print("\n--- Initiating Okta Device Authorization ---")
    try:
        response = requests.post(auth_url, headers=headers, data=data)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
        device_auth_response = response.json()

        device_code = device_auth_response.get('device_code')
        verification_uri_complete = device_auth_response.get('verification_uri_complete')
        user_code = device_auth_response.get('user_code')
        interval = device_auth_response.get('interval', 5)  # Default poll interval
        expires_in = device_auth_response.get('expires_in', 300)  # Default timeout for device code (5 min)

        if not device_code or not verification_uri_complete:
            print("ERROR: Failed to initiate device authorization. Missing device_code or verification_uri_complete.")
            sys.exit(1)

        return {
            "device_code": device_code,
            "verification_uri_complete": verification_uri_complete,
            "user_code": user_code,
            "interval": interval,
            "expires_in": expires_in,
            "start_time": time.time()
        }

    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to connect to Okta for device authorization: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON response from Okta device authorization endpoint: {e}")
        sys.exit(1)


def poll_for_token(okta_org_url, okta_client_id, device_data):
    """
    Polls the Okta token endpoint until the token is received or timeout occurs.
    """
    token_url = f"{okta_org_url}/oauth2/v1/token"
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'client_id': okta_client_id,
        'device_code': device_data['device_code'],
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'
    }

    print("\n--- Waiting for Okta Login Completion ---")
    print("Please complete the login in your browser.")
    print(f"Polling for token every {device_data['interval']} seconds (timeout in {device_data['expires_in']}s).")

    while True:
        elapsed_time = time.time() - device_data['start_time']
        if elapsed_time > device_data['expires_in']:
            print("\nERROR: Device authorization timed out. Please try again.")
            return None

        try:
            response = requests.post(token_url, headers=headers, data=data)
            token_response = response.json()

            if response.status_code == 200:
                access_token = token_response.get('access_token')
                if access_token:
                    print("\nSUCCESS: OAuth token retrieved!")
                    return access_token
                else:
                    print("\nERROR: Token response successful but no 'access_token' found.")
                    return None
            elif token_response.get('error') == 'authorization_pending':
                sys.stdout.write(f"\rAuthorization pending... ({int(elapsed_time)}s elapsed) ")
                sys.stdout.flush()
                time.sleep(device_data['interval'])
            elif token_response.get('error') == 'access_denied':
                print("\nERROR: Access denied by user or Okta. Please try again.")
                return None
            else:
                print(
                    f"\nERROR: Unexpected error fetching token: {token_response.get('error_description', 'Unknown error')}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"\nERROR: Failed to connect to Okta token endpoint during polling: {e}")
            time.sleep(device_data['interval'])  # Wait before retrying
        except json.JSONDecodeError as e:
            print(f"\nERROR: Invalid JSON response from Okta token endpoint during polling: {e}")
            time.sleep(device_data['interval'])  # Wait before retrying


def main():
    okta_org_url, okta_client_id, okta_scopes = get_okta_config()

    device_data = initiate_device_authorization(okta_org_url, okta_client_id, okta_scopes)

    print(f"\n--- Action Required ---")
    print(
        f"Please open this URL in your browser to complete authentication: {device_data['verification_uri_complete']}")
    if device_data.get('user_code'):
        print(f"And enter the user code: {device_data['user_code']}")

    # Automatically open the URL in the default browser
    try:
        webbrowser.open_new(device_data['verification_uri_complete'])
        print("\nOpening the login URL in your default browser...")
    except webbrowser.Error:
        print("\nERROR: Could not automatically open browser. Please open the URL manually.")

    access_token = poll_for_token(okta_org_url, okta_client_id, device_data)

    if access_token:
        print("\n--- Your OAuth Access Token ---")
        print(access_token)
        print("\nToken retrieved successfully.")
    else:
        print("\nFailed to retrieve access token.")


if __name__ == "__main__":
    main()