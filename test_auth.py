#!/usr/bin/env python
"""Test authentication directly"""
import requests
from requests.auth import HTTPBasicAuth
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Test parameters  
base_url = "https://10.10.10.114"
username = "admin"
password = "pfsense"

# Create session
session = requests.Session()
session.verify = False  # Disable SSL verification

# Try authentication
auth_url = f"{base_url}/api/v2/auth/jwt"
print(f"Testing authentication to: {auth_url}")

try:
    response = session.post(
        auth_url,
        auth=HTTPBasicAuth(username, password),
        timeout=5
    )
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 200:
        token_data = response.json()
        print(f"Token data: {token_data}")
    
except Exception as e:
    print(f"Error: {e}")