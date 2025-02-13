// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PatientRecords {
    struct Patient {
        uint256 id;
        string name;
        address owner; // Address of the patient or admin
        bool isActive;
    }

    uint256 public patientCount;
    mapping(uint256 => Patient) public patients;
    mapping(address => uint256[]) public ownerPatients;

    event PatientAdded(uint256 id, string name, address indexed owner);
    event PatientRemoved(uint256 id, address indexed remover);

    modifier onlyOwner(uint256 patientId) {
        require(patients[patientId].owner == msg.sender, "Not authorized");
        _;
    }

    function addPatient(string memory name) public {
        patientCount++;
        patients[patientCount] = Patient({
            id: patientCount,
            name: name,
            owner: msg.sender,
            isActive: true
        });
        ownerPatients[msg.sender].push(patientCount);

        emit PatientAdded(patientCount, name, msg.sender);
    }

    function viewPatient(uint256 patientId) public view returns (Patient memory) {
        require(patients[patientId].isActive, "Patient does not exist or is inactive");
        return patients[patientId];
    }

    function removePatient(uint256 patientId) public onlyOwner(patientId) {
        patients[patientId].isActive = false;

        emit PatientRemoved(patientId, msg.sender);
    }

    function getPatientsByOwner(address owner) public view returns (uint256[] memory) {
        return ownerPatients[owner];
    }
}
