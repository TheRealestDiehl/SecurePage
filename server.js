const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your-secret-key'; // Store in environment variables in production

// Database setup
const db = new sqlite3.Database('diehlDB.sqlite', (err) => {
    if (err) {
        console.error('Error opening database: ', err.message);
        process.exit(1);
    }
    console.log('Connected to the database.');
});

// Middleware
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static('public'));  // Serve static files (like login.html)

// Utility functions
async function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
}

async function verifyPassword(inputPassword, storedHash) {
    return bcrypt.compare(inputPassword, storedHash);
}

function generateToken(user) {
    return jwt.sign({ id: user.id, usergroup: user.usergroup }, SECRET_KEY, { expiresIn: '1h' });
}

function authenticateToken(req, res, next) {
    const token = req.cookies.token; // Retrieve token from cookie

    if (!token) {
        return res.status(401).json({ message: 'Token missing or invalid' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Forbidden' });
        }
        req.user = user;
        next();
    });
}

// Routes

// Registration (For reference, not used in the client)
app.post('/register', async (req, res) => {
    const { username, password, usergroup } = req.body;

    const hashedPassword = await hashPassword(password);

    db.run('INSERT INTO users (username, password, usergroup) VALUES (?, ?, ?)', [username, hashedPassword, usergroup], (err) => {
        if (err) return res.status(500).json({ message: 'Error registering user' });
        res.json({ message: 'User registered successfully' });
    });
});

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Fetch user from database
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return res.status(500).json({ message: 'Error during login' });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        // Verify password
        const passwordMatch = await verifyPassword(password, user.password);
        if (!passwordMatch) return res.status(400).json({ message: 'Invalid credentials' });

        // Generate token and set in cookie
        const token = generateToken(user);
        res.cookie('token', token, {
            httpOnly: true,
            secure: false, // Set to true in production for HTTPS
            maxAge: 3600000, // 1 hour
            sameSite: 'Strict',
        });

        res.json({ message: 'Login successful' });
    });
});

app.get('/dashboard/data', authenticateToken, (req, res) => {
    let query;
    const params = [];

    if (isGroupH(req)) {
        // Group H can access all fields
        query = `SELECT firstname, lastname, gender, age, weight, height, history FROM health`;
    } else if (isGroupR(req)) {
        // Group R cannot access firstname and lastname
        query = `SELECT gender, age, weight, height, history FROM health`;
    } else {
        return res.status(403).json({ message: 'Access denied.' });
    }

    db.all(query, params, (err, rows) => {
        if (err) {
            console.error('Error querying health data:', err.message);
            return res.status(500).json({ message: 'Failed to fetch data.' });
        }

        // Convert gender to M/F
        const formattedRows = rows.map(row => ({
            ...row,
            gender: row.gender === 1 ? 'M' : row.gender === 0 ? 'F' : 'Unknown',
        }));

        res.json(formattedRows);
    });
});


app.post('/dashboard/query', authenticateToken, (req, res) => {
    const { field, value } = req.body;

    const allowedFieldsForAllGroups = ["gender", "age", "weight", "height", "history"];
    const allowedFieldsForGroupH = ["firstname", "lastname", ...allowedFieldsForAllGroups];

    // Determine allowed fields based on the user's group
    const allowedFields = isGroupH(req) ? allowedFieldsForGroupH : allowedFieldsForAllGroups;

    // Validate field
    if (!allowedFields.includes(field)) {
        return res.status(400).json({ message: 'Invalid field for query.' });
    }

    // Construct query
    const fieldsToSelect = isGroupH(req)
        ? `firstname, lastname, gender, age, weight, height, history`
        : `gender, age, weight, height, history`;

    const query = `SELECT ${fieldsToSelect} FROM health WHERE ${field} = ?`;

    db.all(query, [value], (err, rows) => {
        if (err) {
            console.error('Error querying health data:', err.message);
            return res.status(500).json({ message: 'Failed to fetch data.' });
        }

        // Convert gender to M/F
        const formattedRows = rows.map(row => ({
            ...row,
            gender: row.gender === 1 ? 'M' : row.gender === 0 ? 'F' : 'Unknown',
        }));

        res.json(formattedRows);
    });
});

app.post('/dashboard/add', authenticateToken, (req, res) => {
    if (!isGroupH(req)) {
        return res.status(403).json({ message: 'Only users from group H can add data.' });
    }

    const { firstname, lastname, gender, age, weight, height, history } = req.body;

    if (!firstname || !lastname || gender == null || !age || !weight || !height || !history) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    const query = `INSERT INTO health (firstname, lastname, gender, age, weight, height, history) VALUES (?, ?, ?, ?, ?, ?, ?)`;

    db.run(query, [firstname, lastname, gender, age, weight, height, history], function (err) {
        if (err) {
            console.error('Error adding data:', err.message);
            return res.status(500).json({ message: 'Failed to add data.' });
        }
        res.json({ message: 'Data added successfully.', id: this.lastID });
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
