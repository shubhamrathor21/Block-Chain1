from flask import Flask, jsonify, request

# Flask App Initialization
app = Flask(__name__)

# Mock patient data (Replace this with database or IPFS integration later)
patient_data = {
    "walletAddress": "0x1234567890abcdef",
    "fullName": "John Doe",
    "dob": "1990-01-01",
    "gender": "Male",
    "bloodGroup": "A+",
    "address": "123 Main Street, City, Country",
    "hhNumber": "1234567890",
    "email": "john.doe@example.com"
}

@app.route('/profile', methods=['GET'])
def get_profile():
    """
    API endpoint to fetch the patient profile.
    """
    return jsonify({"success": True, "patientData": patient_data}), 200


@app.route('/profile', methods=['POST'])
def update_profile():
    """
    API endpoint to update the patient profile.
    """
    try:
        # Parse the JSON request body
        data = request.json

        # Update the patient profile with new data
        patient_data.update({
            "walletAddress": data.get("walletAddress", patient_data["walletAddress"]),
            "fullName": data.get("fullName", patient_data["fullName"]),
            "dob": data.get("dob", patient_data["dob"]),
            "gender": data.get("gender", patient_data["gender"]),
            "bloodGroup": data.get("bloodGroup", patient_data["bloodGroup"]),
            "address": data.get("address", patient_data["address"]),
            "hhNumber": data.get("hhNumber", patient_data["hhNumber"]),
            "email": data.get("email", patient_data["email"])
        })

        # Respond with the updated profile data
        return jsonify({"success": True, "message": "Profile updated successfully", "updatedData": patient_data}), 200

    except Exception as e:
        # Handle any unexpected errors
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == "__main__":
    # Run the Flask app
    app.run(debug=True)
