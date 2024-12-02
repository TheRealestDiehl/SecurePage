const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const SECRET_KEY = "your-secret-key"; // Store in environment variables in production
const AES_KEY = crypto.randomBytes(32); // 256-bit AES key
const AES_IV = crypto.randomBytes(16);  // 16-byte IV

// Database setup
const db = new sqlite3.Database("diehlDB.sqlite", (err) => {
    if (err) {
        console.error("Error opening database: ", err.message);
        process.exit(1);
    } else {
        console.log("Connected to the database.");
    }
});

// Middleware
app.use(bodyParser.json());
app.use(express.static("public"));

// Utility Functions
async function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
}

async function verifyPassword(inputPassword, storedHash) {
    return bcrypt.compare(inputPassword, storedHash);
}

function generateToken(user) {
    return jwt.sign({ id: user.id, usergroup: user.usergroup }, SECRET_KEY, { expiresIn: "1h" });
}

function authenticateToken(req, res, next) {
    const token = req.headers["authorization"];
    if (!token) {
        console.log("Token missing");
        return res.status(401).json({ message: "Token missing" });
    }

    // Verify the token
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            console.log("Invalid token:", err);
            return res.status(403).json({ message: "Forbidden" });  // Return Forbidden if token is invalid
        }
        req.user = user;  // Attach user info to request
        next();
    });
}

function encryptAttribute(attribute) {
    const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, AES_IV);
    let encrypted = cipher.update(attribute.toString(), "utf8", "hex");
    encrypted += cipher.final("hex");
    return encrypted;
}

function decryptAttribute(encrypted) {
    const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, AES_IV);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
}

function computeDataHash(record) {
    const dataString = `${record.firstname}${record.lastname}${record.gender}${record.age}${record.weight}${record.height}${record.history}`;
    return crypto.createHash("sha256").update(dataString).digest("hex");
}

// Routes
// Registration
app.post("/register", async (req, res) => {
    const { username, password, usergroup } = req.body;

    if (!["H", "R"].includes(usergroup)) {
        return res.status(400).json({ message: "Invalid usergroup" });
    }

    const hashedPassword = await hashPassword(password);

    db.run(
        "INSERT INTO users (username, password, usergroup) VALUES (?, ?, ?)",
        [username, hashedPassword, usergroup],
        (err) => {
            if (err) return res.status(500).json({ message: "Error registering user" });
            res.json({ message: "User registered successfully" });
        }
    );
});

// Login
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    // Fetch the user from the database
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ message: "Error during login" });
        }
        if (!user) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        // Compare the input password (plaintext) with the stored hashed password
        const passwordMatch = await verifyPassword(password, user.password); // user.password is the hashed password
        if (!passwordMatch) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        // Generate the token if the password matches
        const token = generateToken(user);
        res.json({ message: "Login successful", token });
    });
});


// Query Health Data
app.get("/health", authenticateToken, (req, res) => {
    const fields = req.user.usergroup === "R" ? "id, gender, age, weight, height, history" : "*";
    db.all(`SELECT ${fields} FROM health`, [], (err, rows) => {
        if (err) return res.status(500).json({ message: "Database error" });

        // Decrypt sensitive attributes if necessary
        rows = rows.map((row) => ({
            ...row,
            gender: decryptAttribute(row.gender),
            age: decryptAttribute(row.age.toString()),
        }));

        res.json(rows);
    });
});

// Add Health Data (Only Group H)
app.post("/health", authenticateToken, (req, res) => {
    if (req.user.usergroup !== "H") return res.status(403).json({ message: "Access denied" });

    const { firstname, lastname, gender, age, weight, height, history } = req.body;
    const encryptedGender = encryptAttribute(gender.toString());
    const encryptedAge = encryptAttribute(age.toString());

    const record = { firstname, lastname, gender, age, weight, height, history };
    const dataHash = computeDataHash(record);

    db.run(
        "INSERT INTO health (firstname, lastname, gender, age, weight, height, history, data_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [firstname, lastname, encryptedGender, encryptedAge, weight, height, history, dataHash],
        (err) => {
            if (err) return res.status(500).json({ message: "Database error" });
            res.json({ message: "Data added successfully" });
        }
    );
});

// Endpoint to fetch dashboard data
app.get("/dashboard/data", authenticateToken, (req, res) => {
    const usergroup = req.user.usergroup; // 'H' or 'R'

    // Query health data
    db.all("SELECT * FROM health", [], (err, rows) => {
        if (err) {
            console.error("Error querying health data:", err.message);
            return res.status(500).json({ message: "Failed to fetch data" });
        }

        // Filter data based on usergroup
        const filteredData = rows.map((row) => {
            if (usergroup === "R") {
                // Remove restricted fields for group R (e.g., personal info)
                delete row.firstname;
                delete row.lastname;
            }
            return row;
        });

        res.json({ usergroup, data: filteredData });
    });
});


// Start server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
