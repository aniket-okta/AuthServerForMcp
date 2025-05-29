import os
import requests
import json
import time
from flask import Flask, redirect, request, jsonify, render_template_string

# --- Configuration (Replace with your Okta details) ---
# It's highly recommended to use environment variables for sensitive information.
OKTA_ORG_URL = os.getenv('OKTA_ORG_URL', 'YOUR_OKTA_ORG_URL_HERE')
OKTA_CLIENT_ID = os.getenv('OKTA_CLIENT_ID', 'YOUR_OKTA_CLIENT_ID_HERE')
OKTA_SCOPES = os.getenv('OKTA_SCOPES', 'openid profile email offline_access') # Required for the token

# Basic check for configuration
if OKTA_ORG_URL == 'YOUR_OKTA_ORG_URL_HERE' or OKTA_CLIENT_ID == 'YOUR_OKTA_CLIENT_ID_HERE':
    print("ERROR: Okta configuration not set.")
    print("Please set OKTA_ORG_URL and OKTA_CLIENT_ID environment variables or replace placeholders in the script.")
    exit("Configuration missing. Exiting.")


app = Flask(__name__)

# --- Global variables for POC purposes ---
# In a real application, the token would be stored securely (e.g., encrypted in a database,
# a secrets manager like AWS Secrets Manager or Azure Key Vault, or a secure cache).
# The device code data would also be managed more robustly, possibly with session management.
stored_access_token = None
device_code_data = {} # Stores device_code, verification_uri_complete, interval, etc. temporarily

# --- MCP Server Actions ---

@app.route('/')
def index():
    """Provides instructions for using the server."""
    return """
    <h1>Welcome to the MCP Server POC</h1>
    <p>Use the following endpoints:</p>
    <ul>
        <li><code>/login-user</code>: To initiate the Okta login process.</li>
        <li><code>/get-token</code>: To retrieve the OAuth token after successful login.</li>
    </ul>
    """

@app.route('/login-user', methods=['GET'])
def login_user():
    """
    Initiates the Okta Device Authorization flow.
    Redirects the user (via instruction) to the Okta Verify login page.
    """
    global device_code_data
    global stored_access_token

    # Clear any previously stored token or device code data for a new login attempt
    stored_access_token = None
    device_code_data = {}

    auth_url = f"{OKTA_ORG_URL}/oauth2/v1/device/authorize"
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'client_id': OKTA_CLIENT_ID,
        'scope': OKTA_SCOPES
    }

    app.logger.info("Initiating Okta device authorization...")
    try:
        response = requests.post(auth_url, headers=headers, data=data)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        device_auth_response = response.json()

        device_code = device_auth_response.get('device_code')
        verification_uri_complete = device_auth_response.get('verification_uri_complete')
        interval = device_auth_response.get('interval', 5) # Default poll interval
        expires_in = device_auth_response.get('expires_in', 300) # Default timeout for device code (5 min)

        if not device_code or not verification_uri_complete:
            app.logger.error("Failed to get device_code or verification_uri_complete from Okta.")
            return jsonify({"error": "Failed to initiate device authorization. Missing required data."}), 500

        # Store device code data temporarily for polling
        device_code_data = {
            "device_code": device_code,
            "verification_uri_complete": verification_uri_complete,
            "interval": interval,
            "expires_in": expires_in,
            "start_time": time.time() # Mark the start time for timeout calculation
        }

        app.logger.info(f"Device authorization initiated. User needs to visit: {verification_uri_complete}")
        # Present the user with the URL and a button to manually trigger token fetching (polling simulation)
        return render_template_string(
            """
            <h2>Okta Login Initiated</h2>
            <p>Please open the following URL in your browser and complete the authentication process:</p>
            <p><a href="{{ verification_uri_complete }}" target="_blank">{{ verification_uri_complete }}</a></p>
            <p>You may also see a user code: <strong>{{ user_code }}</strong> (if provided by Okta, otherwise disregard)</p>
            <p>Once you complete the login in your browser, click the button below to fetch the token.</p>
            <form action="/fetch-token" method="post">
                <input type="submit" value="Fetch Token Now">
            </form>
            <p>The device code will expire in {{ expires_in }} seconds.</p>
            <p><i>Note: For this POC, clicking 'Fetch Token Now' manually triggers a single poll attempt. A real-world application would poll automatically in the background.</i></p>
            """,
            verification_uri_complete=verification_uri_complete,
            user_code=device_auth_response.get('user_code', 'N/A'),
            expires_in=expires_in
        )

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error initiating Okta device authorization: {e}")
        return jsonify({"error": f"Failed to connect to Okta: {e}"}), 500
    except json.JSONDecodeError as e:
        app.logger.error(f"Error decoding JSON from Okta response: {e}")
        return jsonify({"error": f"Invalid JSON response from Okta: {e}"}), 500


@app.route('/fetch-token', methods=['POST'])
def fetch_token():
    """
    Polls the Okta token endpoint using the device code.
    This simulates the continuous polling logic from the PowerShell script.
    """
    global stored_access_token
    global device_code_data

    if not device_code_data:
        return jsonify({"message": "Please initiate login via /login-user first."}), 400

    if stored_access_token:
        return jsonify({"message": "Token already fetched and stored. Use /get-token to retrieve it."}), 200

    device_code = device_code_data.get('device_code')
    expires_in = device_code_data.get('expires_in', 300)
    start_time = device_code_data.get('start_time', time.time()) # Ensure start_time is set

    elapsed_time = time.time() - start_time
    if elapsed_time > expires_in:
        device_code_data = {} # Clear expired device code data
        app.logger.warning("Device authorization timed out.")
        return jsonify({"message": "Authorization timed out. Please restart the login process via /login-user."}), 408

    token_url = f"{OKTA_ORG_URL}/oauth2/v1/token"
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'client_id': OKTA_CLIENT_ID,
        'device_code': device_code,
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'
    }

    app.logger.info(f"Attempting to fetch token (elapsed: {elapsed_time:.2f}s)...")
    try:
        response = requests.post(token_url, headers=headers, data=data)
        token_response = response.json()

        if response.status_code == 200:
            access_token = token_response.get('access_token')
            if access_token:
                stored_access_token = access_token
                # Clear device code data after successful token retrieval
                device_code_data = {}
                app.logger.info("OAuth token successfully retrieved and stored.")
                return jsonify({"message": "OAuth token successfully retrieved and stored. You can now use /get-token."}), 200
            else:
                app.logger.error("Token response successful but no access_token found.")
                return jsonify({"message": "Token response successful but no access_token found."}), 500
        elif token_response.get('error') == 'authorization_pending':
            # This is expected during polling if the user hasn't completed authorization
            app.logger.info("Authorization pending. User has not completed login yet.")
            return jsonify({"message": f"Authorization pending. Please complete login in Okta Verify and try again. Elapsed time: {elapsed_time:.2f}s"}), 202
        elif token_response.get('error') == 'access_denied':
            device_code_data = {} # Clear device code data on denial
            app.logger.warning("Access denied by user or Okta.")
            return jsonify({"message": "Access denied by user or Okta. Please try again."}), 403
        else:
            app.logger.error(f"Unexpected error fetching token: {token_response}")
            return jsonify({"error": f"Failed to fetch token: {token_response.get('error_description', 'Unknown error')}"}), 500

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error connecting to Okta token endpoint: {e}")
        return jsonify({"error": f"Failed to connect to Okta to fetch token: {e}"}), 500
    except json.JSONDecodeError as e:
        app.logger.error(f"Error decoding JSON from Okta token response: {e}")
        return jsonify({"error": f"Invalid JSON response from Okta token endpoint: {e}"}), 500


@app.route('/get-token', methods=['GET'])
def get_token():
    """Returns the securely stored OAuth access token."""
    global stored_access_token
    if stored_access_token:
        # In a real scenario, you might return specific claims from the token
        # or use it to make further API calls, rather than expose the raw token directly.
        app.logger.info("Returning stored access token.")
        return jsonify({"access_token": stored_access_token}), 200
    else:
        app.logger.info("No token currently stored.")
        return jsonify({"message": "No token currently stored. Please initiate login via /login-user first."}), 404

# --- Main execution ---
if __name__ == '__main__':
    print("Starting MCP Server POC...")
    print(f"Okta Org URL: {OKTA_ORG_URL}")
    print(f"Okta Client ID: {OKTA_CLIENT_ID}")
    print("\nAccess the server at http://127.0.0.1:5000/")
    print("Endpoints:")
    print("  GET /login-user: Initiates Okta authentication.")
    print("  POST /fetch-token: Attempts to retrieve the token after user authorization.")
    print("  GET /get-token: Retrieves the stored OAuth token.")
    print("\nPress Ctrl+C to stop the server.")
    # For a POC, debug=True is acceptable. For production, use a WSGI server like Gunicorn.
    app.run(debug=True, port=5000)

    #Initial Commit