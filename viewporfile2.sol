// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UserProfile {
    struct Profile {
        string fullName;
        string dob;
        string gender;
        string bloodGroup;
        string homeAddress;
        string hhNumber;
        string email;
        bool exists; // Check if profile exists
    }

    mapping(address => Profile) private profiles;

    // Create or Update Profile
    function setProfile(
        string memory _fullName,
        string memory _dob,
        string memory _gender,
        string memory _bloodGroup,
        string memory _homeAddress,
        string memory _hhNumber,
        string memory _email
    ) public {
        profiles[msg.sender] = Profile({
            fullName: _fullName,
            dob: _dob,
            gender: _gender,
            bloodGroup: _bloodGroup,
            homeAddress: _homeAddress,
            hhNumber: _hhNumber,
            email: _email,
            exists: true
        });
    }

    // Fetch Profile of Logged-In User
    function getMyProfile() public view returns (
        string memory,
        string memory,
        string memory,
        string memory,
        string memory,
        string memory,
        string memory
    ) {
        require(profiles[msg.sender].exists, "Profile does not exist");
        Profile memory userProfile = profiles[msg.sender];
        return (
            userProfile.fullName,
            userProfile.dob,
            userProfile.gender,
            userProfile.bloodGroup,
            userProfile.homeAddress,
            userProfile.hhNumber,
            userProfile.email
        );
    }
}
