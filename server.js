const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '12A34d56i',
    database: 'communication_ltd'
});

// Connect to database
db.connect((err) => {
    if (err) {
        console.error('Error connecting to database:', err);
        console.error('Error code:', err.code);
        console.error('Error message:', err.message);
        return;
    }
    console.log('Connected to MySQL database');
});

// Register route
app.post('/register', (req, res) => {
    const { username, password, email } = req.body;

    const query = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
    db.query(query, [username, password, email], (err, results) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                res.status(400).json({ error: 'Username already exists' });
            } else {
                res.status(500).json({ error: 'Error registering user' });
            }
            return;
        }
        res.json({ message: 'User registered successfully' });
    });
});

// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) {
            res.status(500).json({ error: 'Error during login' });
            return;
        }

        if (results.length === 0) {
            res.status(401).json({ error: 'Incorrect username' });
            return;
        }

        if (results[0].password !== password) {
            res.status(401).json({ error: 'Incorrect password' });
            return;
        }

        res.json({ message: 'Login successful' });
    });
});

// Add customer route
app.post('/add-customer', (req, res) => {
    const { name, email, address, package_type } = req.body;

    const query = 'INSERT INTO customers (name, email, address, package_type) VALUES (?, ?, ?, ?)';
    db.query(query, [name, email, address, package_type], (err, results) => {
        if (err) {
            res.status(500).json({ error: 'Error adding customer' });
            return;
        }
        res.json({ message: `Customer ${name} added successfully` });
    });
});

// Change password route
app.post('/change-password', (req, res) => {
    const { username, newPassword } = req.body;

    const query = 'UPDATE users SET password = ? WHERE username = ?';
    db.query(query, [newPassword, username], (err, results) => {
        if (err) {
            res.status(500).json({ error: 'Error changing password' });
            return;
        }

        if (results.affectedRows === 0) {
            res.status(401).json({ error: 'User not found' });
            return;
        }

        res.json({ message: 'Password changed successfully' });
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
}); 