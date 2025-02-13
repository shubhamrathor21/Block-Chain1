// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureLabReports {
    // Define a structure to hold lab report details
    struct LabReport {
        string recordId;
        string doctorName;
        string patientName;
        uint256 age;
        string gender;
        string bloodGroup;
        string patientWallet;
        string diagnosticWallet;
        string reportHash; // Hash of the uploaded report file
        uint256 timestamp; // Time of record creation
    }

    // Mapping to store lab reports by record ID
    mapping(string => LabReport) private labReports;

    // Event to log the creation of a new lab report
    event LabReportCreated(
        string recordId,
        string doctorName,
        string patientName,
        uint256 age,
        string gender,
        string bloodGroup,
        string patientWallet,
        string diagnosticWallet,
        string reportHash,
        uint256 timestamp
    );

    // Function to create a lab report
    function createLabReport(
        string memory _recordId,
        string memory _doctorName,
        string memory _patientName,
        uint256 _age,
        string memory _gender,
        string memory _bloodGroup,
        string memory _patientWallet,
        string memory _diagnosticWallet,
        string memory _reportHash
    ) public {
        require(bytes(_recordId).length > 0, "Record ID is required");
        require(bytes(_doctorName).length > 0, "Doctor Name is required");
        require(bytes(_patientName).length > 0, "Patient Name is required");
        require(_age > 0, "Valid Age is required");
        require(bytes(_gender).length > 0, "Gender is required");
        require(bytes(_bloodGroup).length > 0, "Blood Group is required");
        require(bytes(_patientWallet).length > 0, "Patient Wallet is required");
        require(bytes(_diagnosticWallet).length > 0, "Diagnostic Wallet is required");
        require(bytes(_reportHash).length > 0, "Report hash is required");

        // Ensure the record ID is unique
        require(
            bytes(labReports[_recordId].recordId).length == 0,
            "Record ID already exists"
        );

        // Create and store the lab report
        LabReport memory newReport = LabReport(
            _recordId,
            _doctorName,
            _patientName,
            _age,
            _gender,
            _bloodGroup,
            _patientWallet,
            _diagnosticWallet,
            _reportHash,
            block.timestamp
        );

        labReports[_recordId] = newReport;

        // Emit event for report creation
        emit LabReportCreated(
            _recordId,
            _doctorName,
            _patientName,
            _age,
            _gender,
            _bloodGroup,
            _patientWallet,
            _diagnosticWallet,
            _reportHash,
            block.timestamp
        );
    }

    // Function to retrieve a lab report
    function getLabReport(string memory _recordId)
        public
        view
        returns (
            string memory doctorName,
            string memory patientName,
            uint256 age,
            string memory gender,
            string memory bloodGroup,
            string memory patientWallet,
            string memory diagnosticWallet,
            string memory reportHash,
            uint256 timestamp
        )
    {
        require(
            bytes(labReports[_recordId].recordId).length > 0,
            "Lab report not found"
        );

        LabReport memory report = labReports[_recordId];
        return (
            report.doctorName,
            report.patientName,
            report.age,
            report.gender,
            report.bloodGroup,
            report.patientWallet,
            report.diagnosticWallet,
            report.reportHash,
            report.timestamp
        );
    }
}
