const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");

const app = express();
const PORT = 3000;

// AES Encryption Settings
const AES_KEY = crypto.randomBytes(32); // 256-bit AES key (32 bytes)
const AES_IV = crypto.randomBytes(16);  // 16 bytes IV for AES encryption

// Database setup: Connect to the existing database 'diehlDB.sqlite'
const db = new sqlite3.Database("diehlDB.sqlite", (err) => {
    if (err) {
        console.error("Error opening database: ", err.message);
        process.exit(1);  // Exit if the database can't be opened
    } else {
        console.log("Connected to the existing database 'diehlDB.sqlite'");
    }
});

// Middleware
app.use(bodyParser.json());
app.use(express.static("public"));

// Serve the index page (default home page)
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});

// Ensure the users table exists (if not, you can create it)
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);
});

// Hash password with SHA-256 (using the crypto module)
function hashPassword(password) {
    return crypto.createHash("sha256").update(password).digest("hex");
}

// Register endpoint
app.post("/register", (req, res) => {
    const { username, password } = req.body;

    // Check if username already exists
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (err) {
            return res.status(500).json({ message: "Error checking username" });
        }
        if (row) {
            return res.status(400).json({ message: "Username already exists" });
        }

        // Hash the password with SHA-256
        const hashedPassword = hashPassword(password);

        // Insert new user into the database
        db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function (err) {
            if (err) {
                return res.status(500).json({ message: "Error registering user" });
            }
            res.json({ message: "User registered successfully" });
        });
    });
});

// Login endpoint
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    // Find the user by username
    db.get("SELECT password FROM users WHERE username = ?", [username], (err, row) => {
        if (err) {
            return res.status(500).json({ message: "Error during login" });
        }
        if (!row) {
            return res.status(400).json({ message: "Invalid username or password" });
        }

        // Hash the provided password and compare with stored hash
        const hashedPassword = hashPassword(password);
        if (hashedPassword === row.password) {
            res.json({ message: "Login successful" });
        } else {
            res.status(400).json({ message: "Invalid username or password" });
        }
    });
});

// AES Encryption (for other sensitive data, if needed)
function encryptData(data) {
    const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, AES_IV);
    let encrypted = cipher.update(data, "utf8", "hex");
    encrypted += cipher.final("hex");
    return encrypted;
}

function decryptData(encryptedData) {
    const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, AES_IV);
    let decrypted = decipher.update(encryptedData, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
}

// Start server
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});