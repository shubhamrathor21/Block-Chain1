import os
import json
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3
import bcrypt
import re
import traceback

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# IPFS endpoint (your local IPFS or public gateway)
IPFS_API_URL = os.getenv("IPFS_API_URL", "http://localhost:5001/api/v0")

# Ganache Ethereum connection
ganache_url = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")
web3 = Web3(Web3.HTTPProvider(ganache_url))

# Check if Ganache is connected
if not web3.is_connected():
    print("Error: Unable to connect to Ganache!")
    exit(1)
print("Connected to Ganache!")

# Function to check IPFS connection
def check_ipfs_connection():
    try:
        response = requests.post(f"{IPFS_API_URL}/id", timeout=5)
        if response.status_code == 200:
            return True
        else:
            print("Error: IPFS connection failed with status code:", response.status_code)
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to connect to IPFS. Details: {e}")
        return False

# Dictionaries to store user data for different roles
patient_data = {}
doctor_data = {}
diagnostic_data = {}

# Email validation
def validate_email(email):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

# Password validation
def validate_password(password):
    return (
        len(password) >= 8 and
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password)
    )

# Function to interact with IPFS to add JSON data
def add_to_ipfs(data):
    try:
        response = requests.post(
            f"{IPFS_API_URL}/add",
            files={"file": json.dumps(data).encode('utf-8')},
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        return response.json().get("Hash")
    except requests.exceptions.RequestException as e:
        print(f"Error interacting with IPFS: {e}")
        return None

# Function to fetch data from IPFS using the hash
def get_from_ipfs(ipfs_hash):
    try:
        response = requests.get(f"{IPFS_API_URL}/cat?arg={ipfs_hash}")
        response.raise_for_status()
        return json.loads(response.text)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from IPFS: {e}")
        return None

@app.route("/register/patient", methods=["POST"])
def register_patient():
    try:
        if not check_ipfs_connection():
            return jsonify({"error": "IPFS service is not available"}), 503

        data = request.json
        wallet_address = data.get("walletAddress")
        full_name = data.get("fullName")
        dob = data.get("dob")
        gender = data.get("gender")
        password = data.get("password")
        confirm_password = data.get("confirmPassword")
        email = data.get("email")
        blood_group = data.get("bloodGroup")
        address = data.get("address")

        if not all([wallet_address, full_name, dob, gender, password, email, blood_group, address]):
            return jsonify({"error": "All fields are required"}), 400

        if not web3.is_address(wallet_address):
            return jsonify({"error": "Invalid Ethereum wallet address"}), 400

        if not validate_email(email):
            return jsonify({"error": "Invalid email format"}), 400

        if password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400

        if not validate_password(password):
            return jsonify({
                "error": "Password must be at least 8 characters long and contain uppercase, lowercase, and numeric characters"
            }), 400

        if wallet_address in patient_data:
            return jsonify({"error": "Patient already registered"}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        patient_info = {
            "walletAddress": wallet_address,
            "fullName": full_name,
            "dob": dob,
            "gender": gender,
            "email": email,
            "bloodGroup": blood_group,
            "address": address,
            "passwordHash": hashed_password.decode('utf-8')
        }

        ipfs_hash = add_to_ipfs(patient_info)
        if ipfs_hash:
            patient_data[wallet_address] = ipfs_hash
            return jsonify({
                "message": "Patient registered successfully",
                "ipfsHash": ipfs_hash,
                "fullName": full_name,
                "redirectUrl": "/patientdash.html"
            }), 200
        else:
            return jsonify({"error": "Failed to store data on IPFS"}), 500

    except Exception:
        print(traceback.format_exc())
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route("/login", methods=["POST"])
def login():
    try:
        if not check_ipfs_connection():
            return jsonify({"error": "IPFS service is not available"}), 503

        data = request.json
        wallet_address = data.get("walletAddress")
        password = data.get("password")
        role = data.get("role")

        if role not in ["patient", "doctor", "diagnostic"]:
            return jsonify({"error": "Invalid role"}), 400

        user_store = {
            "patient": patient_data,
            "doctor": doctor_data,
            "diagnostic": diagnostic_data
        }.get(role)

        ipfs_hash = user_store.get(wallet_address)
        if not ipfs_hash:
            return jsonify({"error": f"{role.capitalize()} not found"}), 404

        user_info = get_from_ipfs(ipfs_hash)
        if user_info is None:
            return jsonify({"error": "Failed to fetch data from IPFS"}), 500

        stored_password_hash = user_info.get("passwordHash")
        if not bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
            return jsonify({"error": "Invalid password"}), 401

        redirect_url = "/patientdash.html" if role == "patient" else (
            "/doctordash.html" if role == "doctor" else "/diagnosticdash.html"
        )
        display_name = user_info.get("fullName") if role != "diagnostic" else user_info.get("centerName")

        user_info_safe = {k: v for k, v in user_info.items() if k != 'passwordHash'}
        return jsonify({
            "message": "Login successful",
            "userData": user_info_safe,
            "redirectUrl": redirect_url,
            "displayName": display_name
        }), 200

    except Exception:
        print(traceback.format_exc())
        return jsonify({"error": "An unexpected error occurred"}), 500

if __name__ == "__main__":
    if check_ipfs_connection():
        print("Connected to IPFS!")
        app.run(debug=True)
    else:
        print("Error: IPFS service is not available. Please check your IPFS configuration.")
