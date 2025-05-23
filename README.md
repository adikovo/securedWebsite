# Communication_LTD Information System

This is an intentionally insecure web system for Communication_LTD, a fictional telecommunications company.

## Setup Instructions

1. Install MySQL on your system if not already installed
2. Install Node.js and npm if not already installed
3. Clone this repository
4. Install dependencies:
   ```bash
   npm install
   ```
5. Set up the database:
   - Open MySQL command line or a MySQL client
   - Run the contents of `database.sql` to create the database and tables
6. Update the database connection settings in `server.js`:
   - Set your MySQL username and password
7. Start the server:
   ```bash
   npm start
   ```

## API Endpoints

### Register New User
- **POST** `/register`
- Body: `{ "username": "string", "password": "string", "email": "string" }`

### Login
- **POST** `/login`
- Body: `{ "username": "string", "password": "string" }`

### Add Customer
- **POST** `/add-customer`
- Body: `{ "name": "string", "email": "string", "address": "string", "package_type": "string" }`

### Change Password
- **POST** `/change-password`
- Body: `{ "username": "string", "currentPassword": "string", "newPassword": "string" }`

## Security Notice

This system is intentionally insecure and should not be used in production. It includes:
- Plain text password storage
- No password complexity requirements
- No input validation
- No encryption
- Detailed error messages
- Direct database queries without parameterization 