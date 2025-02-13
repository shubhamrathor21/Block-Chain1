// Register a user
async function registerUser(role, data) {
    try {
        const response = await fetch("http://127.0.0.1:5000/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ role, data }),
        });

        const result = await response.json();
        if (response.ok) {
            console.log("Registration Successful:", result);
        } else {
            console.error("Error:", result.error);
        }
    } catch (error) {
        console.error("Error:", error);
    }
}

// Get data from IPFS
async function getData(ipfsHash) {
    try {
        const response = await fetch(`http://127.0.0.1:5000/get-data?ipfs_hash=${ipfsHash}`);
        const result = await response.json();
        if (response.ok) {
            console.log("Data Retrieved:", result.data);
        } else {
            console.error("Error:", result.error);
        }
    } catch (error) {
        console.error("Error:", error);
    }
}

// Example Usage
registerUser("user", { name: "Alice", age: 25 });
getData("QmExampleHash");
