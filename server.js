// Communication_LTD Backend Server
// Node.js/Express server that handles database operations for the secured web application
// This server works in conjunction with the Flask frontend to provide secure user management

const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const port = 3000;

// Color codes for console output
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m'
};

// Load environment variables
require('dotenv').config();

// Middleware setup
app.use(cors());                    // Enable Cross-Origin Resource Sharing
app.use(bodyParser.json());         // Parse JSON request bodies

// Database connection configuration
require('dotenv').config();
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// Establish database connection
db.connect((err) => {
    if (err) {
        console.error(`${colors.red}Error connecting to database:${colors.reset}`, err);
        console.error(`${colors.red}Error code:${colors.reset}`, err.code);
        console.error(`${colors.red}Error message:${colors.reset}`, err.message);
        return;
    }
    console.log(`${colors.green}Connected to MySQL database${colors.reset}`);
});

// User Registration Route
// Handles new user registration with hashed passwords and salts
app.post('/register', (req, res) => {
    const { username, password, email, password_salt } = req.body;

    // Validate required fields
    if (!username || !password || !email || !password_salt) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // Insert new user into database
    const query = `
        INSERT INTO users (username, password, password_salt, email)
        VALUES (?, ?, ?, ?)
    `;

    db.query(query, [username, password, password_salt, email], (err, results) => {
        if (err) {
            console.error(`${colors.red}[REGISTER ERROR]${colors.reset}`, err);
            if (err.code === 'ER_DUP_ENTRY') {
                return res.status(400).json({ error: 'Username already exists' });
            } else {
                return res.status(500).json({ error: 'Error registering user' });
            }
        }

        console.log(`${colors.green}[REGISTER SUCCESS] User '${username}' registered successfully${colors.reset}`);
        res.json({ message: 'User registered successfully' });
    });
});

// User Login Route
// Retrieves user credentials for Flask to verify
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Query user data from database
    const query = 'SELECT id, username, password, password_salt FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) {
            console.error(`${colors.red}[LOGIN ERROR]${colors.reset}`, err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            console.log(`${colors.yellow}[LOGIN ATTEMPT] User '${username}' not found${colors.reset}`);
            return res.status(404).json({ error: 'User not found' });
        }

        console.log(`${colors.green}[LOGIN SUCCESS] User '${username}' login data retrieved${colors.reset}`);
        // Return user data to Flask for password verification
        res.json(results[0]);
    });
});

// Customer Management Route
// Adds new customers to the business system
app.post('/add-customer', (req, res) => {
    const { name, email, address, package_type } = req.body;

    // Insert customer data into database
    const query = 'INSERT INTO customers (name, email, address, package_type) VALUES (?, ?, ?, ?)';
    db.query(query, [name, email, address, package_type], (err, results) => {
        if (err) {
            console.error(`${colors.red}[CUSTOMER ERROR] Error adding customer:${colors.reset}`, err);
            res.status(500).json({ error: 'Error adding customer' });
            return;
        }
        console.log(`${colors.green}[CUSTOMER SUCCESS] Customer '${name}' added successfully${colors.reset}`);
        res.json({ message: `Customer ${name} added successfully` });
    });
});

// Password Change Route
// Updates user password with new hash and salt
app.post('/change-password', (req, res) => {
    const { username, password, password_salt } = req.body;

    // Update password and salt in database
    const query = 'UPDATE users SET password = ?, password_salt = ? WHERE username = ?';
    db.query(query, [password, password_salt, username], (err, results) => {
        if (err) {
            console.error(`${colors.red}[PASSWORD CHANGE ERROR]${colors.reset}`, err);
            return res.status(500).json({ error: 'Error changing password' });
        }

        if (results.affectedRows === 0) {
            console.log(`${colors.yellow}[PASSWORD CHANGE] User '${username}' not found${colors.reset}`);
            return res.status(404).json({ error: 'User not found' });
        }

        console.log(`${colors.green}[PASSWORD CHANGE SUCCESS] Password changed for user '${username}'${colors.reset}`);
        res.json({ message: 'Password changed successfully' });
    });
});

// Password Verification Route
// Retrieves stored password data for Flask to verify current password
app.post('/verify-password', (req, res) => {
    const { username } = req.body;

    // Get password hash and salt for verification
    const query = 'SELECT password, password_salt FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) {
            console.error(`${colors.red}[VERIFY PASSWORD ERROR]${colors.reset}`, err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            console.log(`${colors.yellow}[VERIFY PASSWORD] User '${username}' not found${colors.reset}`);
            return res.status(404).json({ error: 'User not found' });
        }

        console.log(`${colors.green}[VERIFY PASSWORD SUCCESS] Password data retrieved for user '${username}'${colors.reset}`);
        res.json(results[0]);  // Flask will verify the password with password_manager
    });
});

// Get User Password by ID Route
// Retrieves password data by user ID (used for password reset)
app.post('/get-user-password', (req, res) => {
    const { user_id } = req.body;

    // Query password data by user ID
    const query = 'SELECT password, password_salt FROM users WHERE id = ?';
    db.query(query, [user_id], (err, results) => {
        if (err) {
            console.error(`${colors.red}[GET USER PASSWORD ERROR]${colors.reset}`, err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            console.log(`${colors.yellow}[GET USER PASSWORD] User with ID '${user_id}' not found${colors.reset}`);
            return res.status(404).json({ error: 'User not found' });
        }

        console.log(`${colors.green}[GET USER PASSWORD SUCCESS] Password data retrieved for user ID '${user_id}'${colors.reset}`);
        res.json(results[0]);
    });
});

// Import crypto module for secure token generation
const crypto = require('crypto');

// Password Reset Token Generation Route
// Creates secure reset tokens for password recovery
app.post('/generate-reset-token', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    // Find user by email address
    const findUserQuery = 'SELECT id FROM users WHERE email = ?';
    db.query(findUserQuery, [email], (err, results) => {
        if (err) {
            console.error(`${colors.red}[RESET TOKEN ERROR]${colors.reset}`, err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            console.log(`${colors.yellow}[RESET TOKEN] User with email '${email}' not found${colors.reset}`);
            return res.status(404).json({ error: 'User not found' });
        }

        const user_id = results[0].id;
        // Generate random value using SHA-1 
        const token = crypto.createHash('sha1').update(crypto.randomBytes(64)).digest('hex');
        const expires_at = new Date(Date.now() + 60 * 60 * 1000); // One hour ahead

        // Store reset token in database
        const insertTokenQuery = `
            INSERT INTO password_reset_tokens (user_id, token, expires_at)
            VALUES (?, ?, ?)
        `;

        db.query(insertTokenQuery, [user_id, token, expires_at], (err2) => {
            if (err2) {
                console.error(`${colors.red}[RESET TOKEN ERROR]${colors.reset}`, err2);
                return res.status(500).json({ error: 'Failed to save reset token' });
            }

            console.log(`${colors.green}[RESET TOKEN SUCCESS] Reset token generated for email '${email}'${colors.reset}`);
            return res.json({ token });
        });
    });
});

// Password Reset Route
// Updates user password using valid reset token
app.post('/reset-password', (req, res) => {
    const { user_id, password, password_salt } = req.body;

    // Update password for specified user
    const query = 'UPDATE users SET password = ?, password_salt = ? WHERE id = ?';
    db.query(query, [password, password_salt, user_id], (err, results) => {
        if (err) {
            console.error(`${colors.red}[RESET PASSWORD ERROR]${colors.reset}`, err);
            return res.status(500).json({ error: 'Error resetting password' });
        }

        if (results.affectedRows === 0) {
            console.log(`${colors.yellow}[RESET PASSWORD] User with ID '${user_id}' not found${colors.reset}`);
            return res.status(404).json({ error: 'User not found' });
        }

        console.log(`${colors.green}[RESET PASSWORD SUCCESS] Password reset for user ID '${user_id}'${colors.reset}`);
        res.json({ message: 'Password reset successfully' });
    });
});

// Start the Express server
app.listen(port, () => {
    console.log(`${colors.green}Server running at http://localhost:${port}${colors.reset}`);
});

// Password History Management Route
// Saves password history for security policy enforcement
app.post('/add-password-history', (req, res) => {
    const { user_id, password_hash, password_salt } = req.body;

    // Validate required fields
    if (!user_id || !password_hash || !password_salt) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // Insert password into history table
    const query = `
        INSERT INTO password_history (user_id, password_hash, password_salt)
        VALUES (?, ?, ?)
    `;

    db.query(query, [user_id, password_hash, password_salt], (err, results) => {
        if (err) {
            console.error('[HISTORY ERROR]', err);
            return res.status(500).json({ error: 'Failed to save password history' });
        }

        res.json({ message: 'Password history saved' });
    });
});

// Customer Search Route
// Searches for customers by exact name match
app.get('/search-customer', (req, res) => {
    const { name } = req.query;
    const query = 'SELECT * FROM customers WHERE name = ?';
    db.query(query, [name], (err, results) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ customers: results });
    });
});

// Customer List Route
// Retrieves all customers from database
app.get('/list-customers', (req, res) => {
    db.query('SELECT * FROM customers', (err, results) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ customers: results });
    });
});
