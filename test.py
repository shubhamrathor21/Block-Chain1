import os
import json
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3
import bcrypt
import re
import traceback
import logging
from requests.exceptions import RequestException
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
class Config:
    IPFS_POSSIBLE_URLS = [
        "http://localhost:5001/api/v0",
        "http://127.0.0.1:5001/api/v0",
        "http://localhost:8080/api/v0"
    ]
    GANACHE_URL = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")
    IPFS_TIMEOUT = 10
    IPFS_API_URL = None

# Initialize Web3
web3 = Web3(Web3.HTTPProvider(Config.GANACHE_URL))
if not web3.is_connected():
    raise Exception("Failed to connect to Ganache")

CONTRACT_ADDRESS = "0x870f80823772b3Ef098844A852dDfBeec1061776"  # Replace with deployed contract address
CONTRACT_ABI = [
        {
            "anonymous": False,
            "inputs": [
                {
                    "indexed": True,
                    "internalType": "address",
                    "name": "user",
                    "type": "address"
                },
                {
                    "indexed": False,
                    "internalType": "string",
                    "name": "ipfsHash",
                    "type": "string"
                }
            ],
            "name": "HashStored",
            "type": "event"
        },
        {
            "inputs": [],
            "name": "getHash",
            "outputs": [
                {
                    "internalType": "string",
                    "name": "",
                    "type": "string"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "string",
                    "name": "_ipfsHash",
                    "type": "string"
                }
            ],
            "name": "storeHash",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }
    ]

contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)

# Storage
storage = {
    'patient': {},
    'doctor': {},
    'diagnostic': {}
}

# Utility functions
def check_ipfs_connection() -> bool:
    """Check IPFS connection and set working URL."""
    for url in Config.IPFS_POSSIBLE_URLS:
        try:
            response = requests.post(f"{url}/id", timeout=5)
            if response.status_code == 200:
                Config.IPFS_API_URL = url
                logger.info(f"Connected to IPFS at {url}")
                return True
        except RequestException as e:
            logger.warning(f"Failed to connect to IPFS at {url}: {e}")
    
    logger.error("Could not connect to any IPFS endpoint")
    return False

def check_ganache_connection() -> bool:
    """Verify Ganache connection."""
    try:
        if web3.is_connected():
            logger.info("Connected to Ganache successfully")
            return True
        logger.error("Failed to connect to Ganache")
        return False
    except Exception as e:
        logger.error(f"Error checking Ganache connection: {e}")
        return False
    
def validate_email(email: str) -> bool:
    """Validate email format."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_regex, email))

def validate_password(password: str) -> bool:
    """Validate password strength."""
    return (
        len(password) >= 8 and
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password)
    )

def validate_license_number(license_number: str) -> bool:
    """Validate medical license number format."""
    license_regex = r'^[A-Z0-9]{5,15}$'
    return bool(re.match(license_regex, license_number))

def add_to_ipfs(data: Dict[str, Any]) -> Optional[str]:
    """Add data to IPFS."""
    if not Config.IPFS_API_URL:
        logger.error("IPFS URL not configured")
        return None
    
    try:
        serialized_data = json.dumps(data).encode('utf-8')
        response = requests.post(
            f"{Config.IPFS_API_URL}/add",
            files={"file": serialized_data},
            timeout=Config.IPFS_TIMEOUT
        )
        response.raise_for_status()
        result = response.json()
        return result.get("Hash")
    except Exception as e:
        logger.error(f"Error adding to IPFS: {e}")
        return None

def get_from_ipfs(ipfs_hash: str) -> Optional[Dict[str, Any]]:
    """Retrieve data from IPFS."""
    if not Config.IPFS_API_URL:
        logger.error("IPFS URL not configured")
        return None
    
    try:
        response = requests.get(
            f"{Config.IPFS_API_URL}/cat",
            params={"arg": ipfs_hash},
            timeout=Config.IPFS_TIMEOUT
        )
        response.raise_for_status()
        return json.loads(response.text)
    except Exception as e:
        logger.error(f"Error getting from IPFS: {e}")
        return None

@app.route("/register/<role>", methods=["POST"])
def register(role):
    try:
        # Check IPFS and Ganache connection
        if not check_ipfs_connection():
            return jsonify({"error": "IPFS service unavailable"}), 503
        if not check_ganache_connection():
            return jsonify({"error": "Ganache service unavailable"}), 503

        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        required_fields = {
            "patient": ["walletAddress", "fullName", "dob", "gender", "bloodGroup", "address", "email", "password", "confirmPassword"],
            "doctor": ["walletAddress", "fullName", "specialization", "licenseNumber", "hospitalAffiliation", "email", "phone", "experience", "password", "confirmPassword"],
            "diagnostic": ["walletAddress", "centerName", "licenseNumber", "contactInfo", "email", "address"]
        }.get(role, [])

        if not required_fields:
            return jsonify({"error": "Invalid role"}), 400

        missing = [field for field in required_fields if field not in data]
        if missing:
            return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

        # if not validate_wallet_address(data['walletAddress']):
        #     return jsonify({"error": "Invalid wallet address"}), 400

        if "email" in data and not validate_email(data['email']):
            return jsonify({"error": "Invalid email format"}), 400

        if "password" in data and "confirmPassword" in data:
            if data['password'] != data['confirmPassword']:
                return jsonify({"error": "Passwords do not match"}), 400

            if not validate_password(data['password']):
                return jsonify({"error": "Weak password"}), 400

        # Prepare user data for IPFS
        user_data = {key: data[key] for key in required_fields if key != "confirmPassword"}

        # Store the IPFS hash on the blockchain
        ipfs_hash = add_to_ipfs(user_data)
        if not ipfs_hash:
            return jsonify({"error": "Failed to store data in IPFS"}), 500

        account = data['walletAddress']
        try:
            tx_hash = contract.functions.storeHash(ipfs_hash).transact({"from": account})
            web3.eth.wait_for_transaction_receipt(tx_hash)
        except Exception as e:
            return jsonify({"error": f"Failed to store hash on blockchain: {str(e)}"}), 500

        return jsonify({
            "message": f"{role.capitalize()} registered successfully!",
            "ipfsHash": ipfs_hash,
            "transactionHash": tx_hash.hex()
        }), 201

    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(debug=True)




















app = Flask(__name__)
CORS(app)

GANACHE_URL = "HTTP://127.0.0.1:7545"  # Replace with your Ganache URL
IPFS_API_URL = "http://127.0.0.1:5001/api/v0"  # Replace with your IPFS API URL
CONTRACT_ADDRESS = "0x2A778f111db48Ff42c243076d09a0966F65ADB17"  # Replace with deployed contract address
CONTRACT_ABI = [
	{
		"anonymous": False,
		"inputs": [
			{
				"indexed": True,
				"internalType": "address",
				"name": "user",
				"type": "address"
			},
			{
				"indexed": False,
				"internalType": "string",
				"name": "ipfsHash",
				"type": "string"
			}
		],
		"name": "UserRegistered",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "userAddress",
				"type": "address"
			}
		],
		"name": "getIPFSHash",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "ipfsHash",
				"type": "string"
			}
		],
		"name": "register",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]
web3 = Web3(Web3.HTTPProvider(GANACHE_URL))
contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)

# Helper: IPFS Upload
def upload_to_ipfs(data):
    try:
        files = {"file": json.dumps(data)}
        response = requests.post(f"{IPFS_API_URL}/add", files=files)
        response.raise_for_status()
        return response.json()["Hash"]
    except Exception as e:
        print(f"IPFS upload error: {e}")
        return None

# Helper: Retrieve from IPFS
def retrieve_from_ipfs(ipfs_hash):
    try:
        response = requests.get(f"{IPFS_API_URL}/cat?arg={ipfs_hash}")
        response.raise_for_status()
        return json.loads(response.text)
    except Exception as e:
        print(f"IPFS retrieval error: {e}")
        return None

# Registration endpoint
@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.json
        wallet_address = data.get("walletAddress")
        password = data.get("password")
        user_info = {k: v for k, v in data.items() if k != "password"}
        user_info["passwordHash"] = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        ipfs_hash = upload_to_ipfs(user_info)
        if not ipfs_hash:
            return jsonify({"error": "Failed to store data in IPFS"}), 500

        tx = contract.functions.register(ipfs_hash).buildTransaction({
            "chainId": 1337,
            "gas": 2000000,
            "gasPrice": web3.toWei("10", "gwei"),
            "nonce": web3.eth.getTransactionCount(wallet_address),
        })
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=data["privateKey"])
        web3.eth.send_raw_transaction(signed_tx.rawTransaction)

        return jsonify({"message": "User registered successfully", "ipfsHash": ipfs_hash}), 201
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

# Login endpoint
@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        wallet_address = data.get("walletAddress")
        password = data.get("password")

        ipfs_hash = contract.functions.getIPFSHash(wallet_address).call()
        user_data = retrieve_from_ipfs(ipfs_hash)

        if not user_data or not bcrypt.checkpw(password.encode("utf-8"), user_data["passwordHash"].encode("utf-8")):
            return jsonify({"error": "Invalid credentials"}), 401

        return jsonify({"message": "Login successful", "userData": user_data}), 200
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)