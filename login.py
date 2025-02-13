import os
import json
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3
import bcrypt
import traceback

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Use default values if environment variables are not set
GANACHE_URL = os.getenv("GANACHE_URL", "HTTP://127.0.0.1:7545")
IPFS_API_URL = os.getenv("IPFS_API_URL", "http://localhost:5001/api/v0")

# Web3 connection
web3 = Web3(Web3.HTTPProvider(GANACHE_URL))

# Check Ganache connection
if not web3.is_connected():
    print("Error: Unable to connect to Ganache!")
    exit(1)
print("Connected to Ganache!")

# Helper function: Check IPFS connection
def check_ipfs_connection():
    try:
        response = requests.post(f"{IPFS_API_URL}/id", timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

# Helper function: Store data in IPFS
def store_in_ipfs(data):
    try:
        files = {'file': json.dumps(data)}
        response = requests.post(f"{IPFS_API_URL}/add", files=files)
        if response.status_code == 200:
            return response.json()["QmYBZWTu8iaSspq68DigFHGr7WC8KUY1fF5jzx7ByDvyTL"]  # Return the IPFS hash
        else:
            print("Error storing data in IPFS:", response.text)
            return None
    except Exception as e:
        print("IPFS storage error:", e)
        return None

# Helper function: Retrieve data from IPFS
def retrieve_from_ipfs(ipfs_hash):
    try:
        response = requests.get(f"{IPFS_API_URL}/cat?arg={ipfs_hash}")
        if response.status_code == 200:
            return json.loads(response.text)
        else:
            print("Error retrieving data from IPFS:", response.text)
            return None
    except Exception as e:
        print("IPFS retrieval error:", e)
        return None

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        wallet_address = data.get('walletAddress')
        password = data.get('password')
        full_name = data.get('fullName')

        if not wallet_address or not password or not full_name:
            return jsonify({"error": "Wallet address, password, and full name are required"}), 400

        # Validate Ethereum wallet address format
        if not web3.is_address(wallet_address):
            return jsonify({"error": "Invalid Ethereum wallet address"}), 400

        # Hash the password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Prepare user data
        user_data = {
            "walletAddress": wallet_address,
            "passwordHash": password_hash,
            "fullName": full_name
        }

        # Store user data in IPFS
        ipfs_hash = store_in_ipfs(user_data)
        if not ipfs_hash:
            return jsonify({"error": "Failed to store user data in IPFS"}), 500

        return jsonify({
            "message": "User registered successfully",
            "ipfsHash": ipfs_hash
        }), 201

    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        wallet_address = data.get('walletAddress')
        password = data.get('password')
        ipfs_hash = data.get('ipfsHash')

        if not wallet_address or not password or not ipfs_hash:
            return jsonify({"error": "Wallet address, password, and IPFS hash are required"}), 400

        # Validate Ethereum wallet address format
        if not web3.is_address(wallet_address):
            return jsonify({"error": "Invalid Ethereum wallet address"}), 400

        # Retrieve user data from IPFS
        user_data = retrieve_from_ipfs(ipfs_hash)
        if not user_data or user_data.get("walletAddress") != wallet_address:
            return jsonify({"error": "User not found"}), 404

        # Validate the password
        if not bcrypt.checkpw(password.encode('utf-8'), user_data['passwordHash'].encode('utf-8')):
            return jsonify({"error": "Invalid password"}), 401

        return jsonify({
            "message": "Login successful",
            "fullName": user_data['fullName'],
            "walletAddress": wallet_address
        }), 200

    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": "An unexpected error occurred"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)













@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        wallet_address = data.get('walletAddress')
        password = data.get('password')

        if not wallet_address or not password:
            return jsonify({"error": "Wallet address and password are required"}), 400

        # Validate Ethereum wallet address format
        if not web3.is_address(wallet_address):
            return jsonify({"error": "Invalid Ethereum wallet address"}), 400

        # Interact with the blockchain to get the IPFS hash
        contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
        ipfs_hash = contract.functions.login().call({'from': wallet_address})

        # Retrieve user data from IPFS
        user_data = retrieve_from_ipfs(ipfs_hash)
        if not user_data:
            return jsonify({"error": "User not found"}), 404

        # Validate password
        if not bcrypt.checkpw(password.encode('utf-8'), user_data['passwordHash'].encode('utf-8')):
            return jsonify({"error": "Invalid password"}), 401

        return jsonify({
            "message": "Login successful",
            "fullName": user_data['fullName'],
            "walletAddress": wallet_address
        }), 200

    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": "An unexpected error occurred"}), 500
