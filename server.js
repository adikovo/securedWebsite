const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const port = 3000;

require('dotenv').config();
// Middleware
app.use(cors());
app.use(bodyParser.json());

// Database connection
require('dotenv').config();
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
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
    const { username, password, email, password_salt } = req.body;

    if (!username || !password || !email || !password_salt) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const query = `
        INSERT INTO users (username, password, password_salt, email)
        VALUES (?, ?, ?, ?)
    `;

    db.query(query, [username, password, password_salt, email], (err, results) => {
        if (err) {
            console.error('[REGISTER ERROR]', err);
            if (err.code === 'ER_DUP_ENTRY') {
                return res.status(400).json({ error: 'Username already exists' });
            } else {
                return res.status(500).json({ error: 'Error registering user' });
            }
        }

        res.json({ message: 'User registered successfully' });
    });
});


// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = 'SELECT id, username, password, password_salt FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) {
            console.error("[LOGIN ERROR]", err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // מחזיר את המידע ל-Flask לאימות
        res.json(results[0]);
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
// app.post('/change-password', (req, res) => {
//     const { username, newPassword } = req.body;

//     const query = 'UPDATE users SET password = ? WHERE username = ?';
//     db.query(query, [newPassword, username], (err, results) => {
//         if (err) {
//             res.status(500).json({ error: 'Error changing password' });
//             return;
//         }

//         if (results.affectedRows === 0) {
//             res.status(401).json({ error: 'User not found' });
//             return;
//         }

//         res.json({ message: 'Password changed successfully' });
//     });
// });

// Start server

app.post('/change-password', (req, res) => {
    const { username, password, password_salt } = req.body;

    const query = 'UPDATE users SET password = ?, password_salt = ? WHERE username = ?';
    db.query(query, [password, password_salt, username], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Error changing password' });
        }

        if (results.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'Password changed successfully' });
    });
});

app.post('/verify-password', (req, res) => {
    const { username } = req.body;

    const query = 'SELECT password, password_salt FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(results[0]);  // Flask יאמת את הסיסמה בצד שלו עם password_manager
    });
});


const crypto = require('crypto');

app.post('/generate-reset-token', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    const findUserQuery = 'SELECT id FROM users WHERE email = ?';
    db.query(findUserQuery, [email], (err, results) => {
        if (err) {
            console.error('[DB ERROR]', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user_id = results[0].id;
        const token = crypto.createHash('sha1').update(crypto.randomBytes(64)).digest('hex');
        const expires_at = new Date(Date.now() + 60 * 60 * 1000); // שעה קדימה

        const insertTokenQuery = `
            INSERT INTO password_reset_tokens (user_id, token, expires_at)
            VALUES (?, ?, ?)
        `;

        db.query(insertTokenQuery, [user_id, token, expires_at], (err2) => {
            if (err2) {
                console.error('[TOKEN ERROR]', err2);
                return res.status(500).json({ error: 'Failed to save reset token' });
            }

            return res.json({ token });
        });
    });
});

app.post('/reset-password', (req, res) => {
    const { user_id, password, password_salt } = req.body;

    const query = 'UPDATE users SET password = ?, password_salt = ? WHERE id = ?';
    db.query(query, [password, password_salt, user_id], (err, results) => {
        if (err) {
            console.error('[RESET ERROR]', err);
            return res.status(500).json({ error: 'Error resetting password' });
        }

        if (results.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        console.log('[RESET SUCCESS]', { user_id });
        res.json({ message: 'Password reset successfully' });
    });
});



app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
}); 
