// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract HealthRecords {
    struct Record {
        uint256 id;
        string description;
        string fileHash; // Hash of the file stored off-chain (e.g., IPFS)
        uint256 timestamp;
        address owner;
    }

    uint256 public recordCount;
    mapping(uint256 => Record) public records;
    mapping(address => uint256[]) public userRecords;

    event RecordAdded(uint256 id, address indexed owner);
    event RecordViewed(uint256 id, address indexed viewer);

    modifier onlyOwner(uint256 recordId) {
        require(records[recordId].owner == msg.sender, "Not the owner of the record");
        _;
    }

    function addRecord(string memory description, string memory fileHash) public {
        recordCount++;
        records[recordCount] = Record({
            id: recordCount,
            description: description,
            fileHash: fileHash,
            timestamp: block.timestamp,
            owner: msg.sender
        });
        userRecords[msg.sender].push(recordCount);

        emit RecordAdded(recordCount, msg.sender);
    }

    function viewRecord(uint256 recordId) public view returns (Record memory) {
        Record memory record = records[recordId];
        emit RecordViewed(recordId, msg.sender);
        return record;
    }

    function getRecordsByOwner(address owner) public view returns (uint256[] memory) {
        return userRecords[owner];
    }
}
