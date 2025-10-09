# Epic FHIR Integration Setup Guide

This guide provides step-by-step instructions for setting up an Epic FHIR integration using asymmetric key authentication and OAuth 2.0 Client Credentials Flow for backend systems. Follow these steps to generate keys, create a JWKS file, register an app in Epic’s App Orchard, and use the JWT to obtain an access token for FHIR API calls.

## Step 1: Generate RSA Private Key
- Open Command Prompt in your working folder (e.g., `D:\Emyra`).
- Run the following command to generate a 2048-bit RSA private key:
  ```
  openssl genrsa -out emyra-private.pem 2048
  ```
- **Output**: Creates `emyra-private.pem` (keep this file secret).

## Step 2: Generate Public Key from Private Key
- Run the following command to extract the public key from the private key:
  ```
  openssl rsa -in emyra-private.pem -pubout -out emyra-public.pem
  ```
- **Output**: Creates `emyra-public.pem`, which will be used for JWKS generation.

## Step 3: Create a Self-Signed X.509 Certificate
- Epic requires a certificate for JWT signing. Run:
  ```
  openssl req -new -x509 -key emyra-private.pem -out emyra-public.crt -days 365
  ```
- Fill in the prompts with either dummy or real values. Example:
  ```
  Country Name (2 letter code) [XX]: US
  State or Province Name (full name) []: California
  Locality Name (eg, city) []: San Francisco
  Organization Name (eg, company) []: Emyra Inc
  Organizational Unit Name (eg, section) []: IT Department
  Common Name (e.g. server FQDN or YOUR name) []: Emyra FHIR Connect
  Email Address []: contact@emyra.ai
  ```
- **Output**: Creates `emyra-public.crt`, which Epic will accept for JWT signing key upload.
- **Verify the certificate**:
  ```
  openssl x509 -in emyra-public.crt -text -noout
  ```
- Ensure it shows `Public Key: (2048 bit)`.

## Step 4: Convert Public Key to JWKS JSON
- Create a Python script to convert the public key to JWKS format for non-production use.
- Create a file named `convert_to_jwks.py` with the following content:

```python
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from jwt.utils import base64url_encode

# Load public key
with open("emyra-public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

numbers = public_key.public_numbers()
e = base64url_encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")).decode()
n = base64url_encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")).decode()

jwks = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "emyra-key-001",  # Update with KeyID from emyra-public.crt
            "alg": "RS384",
            "n": n,
            "e": e
        }
    ]
}

with open("jwks.json", "w") as f:
    json.dump(jwks, f, indent=2)

print("✅ JWKS file created: jwks.json")
```

- **Update the `kid` value**:
  - Open `emyra-public.crt` and locate the `Authority Key Identifier` section.
  - Copy the `KeyID` and update the `"kid"` field in the script (e.g., replace `"emyra-key-001"`).
- Run the script:
  ```
  python convert_to_jwks.py
  ```
- **Output**: Creates `jwks.json`, which can be hosted publicly (e.g., on GitHub Pages).

## Step 5: Host JWstoreKS File Publicly
- Epic requires a publicly accessible HTTPS endpoint for the JWKS file (e.g., `https://api.emyra.ai/.well-known/jwks.json`) for non-production/sandbox environments.
- **Hosting on GitHub**:
  - Upload `jwks.json` to a GitHub repository.
  - Open the file in GitHub and click the **Raw** button to get a URL like:
    ```
    https://raw.githubusercontent.com/Manikanta-Champsoft/Emyra_FHIR_Connect/main/jwks.json
    ```
- This URL will be used in the Epic App Orchard registration.
- Epic uses the JWKS during:
  - Testing in the sandbox (non-production).
  - Verifying JWTs before issuing access tokens.

## Step 6: Register App in Epic App Orchard
- Visit the Epic App Orchard site, sign up, and log in.
- Go to the **Build Apps** section and create a new app.
- Provide the application name and select **Application Audience** as **Backend Systems**.
- **Backend Systems**:
  - The chatbot backend uses system-to-system integration with Epic.
  - It uses OAuth 2.0 Client Credentials Flow (no user login).
  - It accesses FHIR data programmatically on behalf of the application.
- **Public Documentation URL**:
  - Epic requires a public-facing URL describing your app (e.g., `https://emyra.ai/fhir-connect`).
  - If no website exists, use a GitHub repo README (e.g., `https://github.com/emyra/emyra-fhir-connect`).
  - The URL must be publicly accessible and describe the app’s purpose without sensitive data.
- Select required APIs and supported FHIR versions (e.g., R4, DSTU2, STU3).
- In the **Non-Production JWK Set URL** section, paste the GitHub raw URL for `jwks.json`.
- Upload `emyra-public.crt` in the **Sandbox JWT Signing Public Key** section.
- Select the **SMART on FHIR Version** (e.g., R4, DSTU2, STU3).
- After submission, you will receive a **Client ID** and **Non-Production Client ID**. Copy the **Non-Production Client ID** for the sandbox environment.

## Step 7: Generate JWT and Fetch FHIR Data
- Use the following Python script to generate a JWT, obtain an access token, and fetch FHIR data.
- Create a file named `fetch_fhir_data.py`:

```python
import jwt
import time
from pathlib import Path
import requests

# =========================
# CONFIGURATION
# =========================

# Path to your private key
PRIVATE_KEY_FILE = "emyra-private.pem"

# Epic Sandbox Non-Production Client ID
CLIENT_ID = "332c4637-f5e1-44ac-b596-b9e253215b65"  # Replace with your Non-Production Client ID

# Sandbox OAuth2 token endpoint
TOKEN_URL = "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token"

# Sandbox FHIR API endpoint (R4)
FHIR_BASE_URL = "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4"

# JWT Header Key ID (must match your certificate)
KID = "c1c5c8bb6e266d869be9e18cc5d0d6305768359c"  # Replace with KeyID from emyra-public.crt

# JWT expiration time (in seconds)
JWT_EXPIRATION = 300  # 5 minutes

# FHIR ID of the patient to fetch
PATIENT_ID = "erXuFYUfucBZaryVksYEcMg3"  # Camila Lopez

# =========================
# STEP 1: Generate JWT
# =========================

private_key = Path(PRIVATE_KEY_FILE).read_text()
now = int(time.time())

payload = {
    "iss": CLIENT_ID,
    "sub": CLIENT_ID,
    "aud": TOKEN_URL,
    "jti": str(now),
    "exp": now + JWT_EXPIRATION
}

headers = {
    "alg": "RS384",
    "kid": KID
}

jwt_token = jwt.encode(payload, private_key, algorithm="RS384", headers=headers)
print("✅ Generated JWT:\n", jwt_token, "\n")

# =========================
# STEP 2: Request Access Token
# =========================

data = {
    "grant_type": "client_credentials",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": jwt_token
}

response = requests.post(TOKEN_URL, data=data)
token_response = response.json()
print("✅ Token Response:\n", token_response, "\n")

if "access_token" not in token_response:
    print("❌ Failed to obtain access token. Please check your JWT and client configuration.")
    exit(1)

access_token = token_response["access_token"]

# =========================
# STEP 3: Fetch Single Patient by FHIR ID
# =========================

headers = {
    "Authorization": f"Bearer {access_token}",
    "Accept": "application/fhir+json"
}

url = f"{FHIR_BASE_URL}/Patient/{PATIENT_ID}"
response = requests.get(url, headers=headers)

# Safely parse JSON
try:
    patient_data = response.json()
    print("✅ Patient Data:\n", patient_data)
except Exception:
    print("❌ Failed to parse JSON. Raw response:")
    print(response.text)

# Optional: Print basic info
if "resourceType" in patient_data and patient_data["resourceType"] == "Patient":
    pid = patient_data.get("id")
    name = patient_data.get("name", [{}])[0].get("text", "N/A") if "name" in patient_data else "N/A"
    gender = patient_data.get("gender", "N/A")
    birthdate = patient_data.get("birthDate", "N/A")
    print(f"\nPatient ID: {pid}, Name: {name}, Gender: {gender}, BirthDate: {birthdate}")
```

- **Update the script**:
  - Replace `CLIENT_ID` with the **Non-Production Client ID** from Epic.
  - Replace `KID` with the `KeyID` from `emyra-public.crt`.
- Run the script:
  ```
  python fetch_fhir_data.py
  ```
- **Output**:
  - Generates a JWT and uses it to obtain an access token.
  - Fetches patient data from the Epic FHIR API using the access token.
  - Prints basic patient information (ID, name, gender, birth date).
- **Next Steps**:
  - Map the response data to a PostgreSQL database based on your business logic.