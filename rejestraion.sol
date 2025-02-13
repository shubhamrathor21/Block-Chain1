// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RegistrationPortal {
    enum Role { Patient, Doctor, Diagnostic }

    struct Patient {
        address walletAddress;
        string fullName;
        string dateOfBirth;
        string gender;
        string bloodGroup;
        string homeAddress;
        string email;
        string hhNumber;
        bytes32 passwordHash;
    }

    struct Doctor {
        address walletAddress;
        string fullName;
        string specialty;
        string licenseNumber;
        uint256 yearsOfExperience;
        string hospitalName;
        string hospitalLocation;
        string gender;
        string consultationMethod; // Online, In-person, Both
        string email;
        string phone;
        bytes32 passwordHash;
    }

    struct DiagnosticCenter {
        address walletAddress;
        string centerName;
        string hospitalName;
        string hhNumber;
        string licenseNumber;
        string addressLocation;
        string email;
        string phone;
        bytes32 passwordHash;
    }

    mapping(address => Patient) public patients;
    mapping(address => Doctor) public doctors;
    mapping(address => DiagnosticCenter) public diagnosticCenters;
    mapping(address => bool) public registered;

    event PatientRegistered(address indexed walletAddress, string fullName);
    event DoctorRegistered(address indexed walletAddress, string fullName);
    event DiagnosticRegistered(address indexed walletAddress, string centerName);

    // Registration for Patients
    function registerPatient(
        string memory _fullName,
        string memory _dateOfBirth,
        string memory _gender,
        string memory _bloodGroup,
        string memory _homeAddress,
        string memory _email,
        string memory _hhNumber,
        string memory _password
    ) public {
        require(!registered[msg.sender], "User already registered");
        patients[msg.sender] = Patient({
            walletAddress: msg.sender,
            fullName: _fullName,
            dateOfBirth: _dateOfBirth,
            gender: _gender,
            bloodGroup: _bloodGroup,
            homeAddress: _homeAddress,
            email: _email,
            hhNumber: _hhNumber,
            passwordHash: keccak256(abi.encodePacked(_password))
        });
        registered[msg.sender] = true;
        emit PatientRegistered(msg.sender, _fullName);
    }

    // Registration for Doctors
    function registerDoctor(
        string memory _fullName,
        string memory _specialty,
        string memory _licenseNumber,
        uint256 _yearsOfExperience,
        string memory _hospitalName,
        string memory _hospitalLocation,
        string memory _gender,
        string memory _consultationMethod,
        string memory _email,
        string memory _phone,
        string memory _password
    ) public {
        require(!registered[msg.sender], "User already registered");
        doctors[msg.sender] = Doctor({
            walletAddress: msg.sender,
            fullName: _fullName,
            specialty: _specialty,
            licenseNumber: _licenseNumber,
            yearsOfExperience: _yearsOfExperience,
            hospitalName: _hospitalName,
            hospitalLocation: _hospitalLocation,
            gender: _gender,
            consultationMethod: _consultationMethod,
            email: _email,
            phone: _phone,
            passwordHash: keccak256(abi.encodePacked(_password))
        });
        registered[msg.sender] = true;
        emit DoctorRegistered(msg.sender, _fullName);
    }

    // Registration for Diagnostic Centers
    function registerDiagnosticCenter(
        string memory _centerName,
        string memory _hospitalName,
        string memory _hhNumber,
        string memory _licenseNumber,
        string memory _addressLocation,
        string memory _email,
        string memory _phone,
        string memory _password
    ) public {
        require(!registered[msg.sender], "User already registered");
        diagnosticCenters[msg.sender] = DiagnosticCenter({
            walletAddress: msg.sender,
            centerName: _centerName,
            hospitalName: _hospitalName,
            hhNumber: _hhNumber,
            licenseNumber: _licenseNumber,
            addressLocation: _addressLocation,
            email: _email,
            phone: _phone,
            passwordHash: keccak256(abi.encodePacked(_password))
        });
        registered[msg.sender] = true;
        emit DiagnosticRegistered(msg.sender, _centerName);
    }

    // Function to check if a wallet is registered
    function isRegistered(address _user) public view returns (bool) {
        return registered[_user];
    }
}
