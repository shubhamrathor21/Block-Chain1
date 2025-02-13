// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UserAuthentication {
    // Define roles
    enum Role { Patient, Doctor, Diagnostic }

    // Structure to store user details
    struct User {
        string hhNumber; // Unique identifier (e.g., Health ID)
        bytes32 passwordHash; // Hashed password
        Role role; // User role
        bool exists; // Check if the user exists
    }

    // Mapping to store users by their wallet address
    mapping(address => User) private users;

    // Events
    event UserRegistered(address indexed userAddress, string hhNumber, Role role);
    event LoginSuccess(address indexed userAddress, Role role);

    // Modifier to check if the user exists
    modifier userExists(address userAddress) {
        require(users[userAddress].exists, "User does not exist.");
        _;
    }

    // Register a new user
    function register(
        string memory _hhNumber,
        string memory _password,
        Role _role
    ) public {
        require(!users[msg.sender].exists, "User already registered.");
        bytes32 hashedPassword = keccak256(abi.encodePacked(_password));
        users[msg.sender] = User(_hhNumber, hashedPassword, _role, true);
        emit UserRegistered(msg.sender, _hhNumber, _role);
    }

    // Login a user
    function login(string memory _hhNumber, string memory _password)
        public
        view
        userExists(msg.sender)
        returns (Role)
    {
        User memory user = users[msg.sender];
        require(
            keccak256(abi.encodePacked(_password)) == user.passwordHash,
            "Invalid credentials."
        );
        require(
            keccak256(abi.encodePacked(_hhNumber)) == keccak256(abi.encodePacked(user.hhNumber)),
            "Invalid HH Number."
        );
        emit LoginSuccess(msg.sender, user.role);
        return user.role;
    }

    // Fetch user role
    function getUserRole(address userAddress) public view userExists(userAddress) returns (Role) {
        return users[userAddress].role;
    }

    // Fetch user details (for debugging or admin purposes)
    function getUserDetails(address userAddress)
        public
        view
        userExists(userAddress)
        returns (string memory, Role)
    {
        User memory user = users[userAddress];
        return (user.hhNumber, user.role);
    }
}
