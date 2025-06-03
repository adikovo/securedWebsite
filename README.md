# Communication_LTD Secured Information System

A comprehensive secured web application for Communication_LTD telecommunications company featuring advanced security measures, password management, and customer data handling.

## Architecture Overview

- **Frontend**: Flask (Python) web application with secure templates
- **Backend**: Node.js/Express API server for database operations
- **Database**: MySQL with security features and audit trails
- **Security**: PBKDF2 password hashing, login attempt tracking, password history, email-based password reset

## Prerequisites

Before setting up the system, ensure you have the following installed:

- **Python 3.8+** with pip
- **Node.js 14+** with npm
- **MySQL 8.0+** or MariaDB 10.3+
- **Git** for cloning the repository

## Complete Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/adikovo/securedWebsite.git
cd securedWebsite
```

### 2. Database Setup

#### Create Database and User
```sql
-- Connect to MySQL as root
mysql -u root -p

-- Create database
CREATE DATABASE communication_ltd_secure;

-- Create dedicated user for the application
CREATE USER 'comm_user'@'localhost' IDENTIFIED BY 'SecurePass123!';
GRANT ALL PRIVILEGES ON communication_ltd_secure.* TO 'comm_user'@'localhost';
FLUSH PRIVILEGES;

-- Use the new database
USE communication_ltd_secure;
```

#### Initialize Database Schema
```bash
# Run the complete database setup
mysql -u comm_user -p communication_ltd_secure < secure_database.sql

# OR if migrating from existing database
mysql -u comm_user -p communication_ltd_secure < migrate_database.sql
```

### 3. Environment Configuration

#### Create Environment File (.env)
Create a `.env` file in the root directory:
```env
# Database Configuration
DB_HOST=localhost
DB_USER=comm_user
DB_PASSWORD=SecurePass123!
DB_NAME=communication_ltd_secure

# Email Configuration (REPLACE WITH YOUR DETAILS)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com     # Replace with your Gmail address
MAIL_PASSWORD=your-app-password        # Replace with your Gmail App Password

# Security Settings (GENERATE YOUR OWN)
FLASK_SECRET_KEY=your-secret-key-here  # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
```

#### Gmail App Password Setup
1. Go to [Google App Passwords](https://myaccount.google.com/apppasswords)
2. Select **"Mail"** as the app
3. Select **"Other"** as the device
4. Enter name: `Communication_LTD_System`
5. Copy the generated 16-character password to `MAIL_PASSWORD`

### 4. Backend (Node.js) Setup

#### Install Dependencies
```bash
npm install
```

#### Required Node.js Packages
The system uses these key packages:
- `express` - Web framework
- `mysql2` - MySQL database driver
- `cors` - Cross-origin resource sharing
- `body-parser` - Request body parsing
- `crypto` - Cryptographic functions

#### Start Backend Server
```bash
npm start
```
**Backend runs on**: `http://localhost:3000`

### 5. Frontend (Flask) Setup

#### Install Python Dependencies
```bash
# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install required packages
pip install flask requests mysql-connector-python python-dotenv
```

#### Required Python Packages
- `flask` - Web framework
- `requests` - HTTP client for backend communication
- `mysql-connector-python` - MySQL database connector
- `python-dotenv` - Environment variable loading

#### Start Flask Application
```bash
python app.py
```
**Frontend runs on**: `http://localhost:5001`

### 6. Password Policy Configuration

Edit `config.json` to customize security settings:
```json
{
    "password_policy": {
        "min_length": 10,
        "require_uppercase": true,
        "require_lowercase": true,
        "require_digits": true,
        "require_special_chars": true,
        "password_history_size": 3,
        "max_login_attempts": 3,
        "login_lockout_duration_minutes": 15,
        "whitelist": [
            "SecurePass123!",
            "StrongP@ssw0rd",
            "ComplexP@ss123"
        ]
    }
}
```

## System Features

### Security Features
- **PBKDF2 Password Hashing**: 100,000 iterations with SHA-256
- **Password History**: Prevents reuse of last 3 passwords
- **Login Rate Limiting**: 3 attempts per 15-minute window
- **Password Reset Tokens**: SHA-1 tokens with 1-hour expiration
- **Input Sanitization**: XSS prevention on all user inputs
- **Session Management**: Secure Flask sessions
- **Audit Logging**: Comprehensive security event tracking

### User Management
- **User Registration**: With password confirmation
- **Secure Login**: Multi-factor validation
- **Password Change**: With current password verification
- **Password Reset**: Email-based token system
- **Session Handling**: Automatic logout and security

### Customer Management
- **Add Customers**: Name, email, address, package type
- **Search Customers**: By name with partial matching
- **List All Customers**: Complete customer database view
- **Data Validation**: Input sanitization and validation

## API Endpoints

### Authentication Endpoints
- `POST /register` - User registration
- `POST /login` - User authentication
- `POST /verify-password` - Password verification
- `POST /change-password` - Password update
- `POST /generate-reset-token` - Password reset request
- `POST /reset-password` - Password reset completion

### Customer Management Endpoints
- `POST /add-customer` - Add new customer
- `GET /search-customer?name=query` - Search customers
- `GET /list-customers` - List all customers

### Utility Endpoints
- `POST /get-user-password` - Get user password details (for history)

## Database Schema

### Core Tables
- **users**: User accounts with hashed passwords
- **customers**: Customer information and packages
- **password_history**: Historical password tracking
- **login_attempts**: Security monitoring and rate limiting
- **password_reset_tokens**: Secure password reset system

### Security Tables
- **login_attempts**: IP tracking and attempt monitoring
- **password_history**: Prevents password reuse
- **password_reset_tokens**: Time-limited reset authorization

## Running the Complete System

### Start All Services
```bash
# Terminal 1: Start MySQL (if not running as service)
sudo systemctl start mysql

# Terminal 2: Start Node.js Backend
npm start

# Terminal 3: Start Flask Frontend
python app.py
```

### Access the Application
1. Open browser to `http://localhost:5001`
2. Register a new account or login with existing credentials
3. Use the system dashboard for customer management

## Security Testing

### Test Password Policy
- Try passwords shorter than 10 characters
- Test without uppercase, lowercase, digits, or special characters
- Verify password history enforcement

### Test Rate Limiting
- Make 3 failed login attempts
- Verify 4th attempt is blocked (even with correct password)
- Wait 15 minutes and verify access is restored

### Test Password Reset
- Request password reset via email
- Verify token expiration (1 hour)
- Test token reuse prevention

## Troubleshooting

### Common Issues

#### Database Connection Errors
```bash
# Check MySQL service
sudo systemctl status mysql

# Test connection
mysql -u comm_user -p communication_ltd_secure
```

#### Backend Connection Issues
```bash
# Check if backend is running
curl http://localhost:3000/health

# Check Node.js logs
npm start
```

#### Email Configuration Issues
- Verify Gmail App Password is correct
- Check firewall settings for SMTP (port 587)
- Test email configuration with simple send

#### Frontend Issues
```bash
# Check Flask logs
python app.py

# Verify backend connectivity
curl http://localhost:3000
```

## Development Notes

### File Structure
```
securedWebsite/
├── app.py                 # Flask frontend application
├── server.js              # Node.js backend server
├── password_utils.py      # Password security utilities
├── config.json           # Security policy configuration
├── secure_database.sql   # Complete database schema
├── migrate_database.sql  # Migration script
├── templates/            # HTML templates
├── static/              # CSS and static files
├── .env                 # Environment variables
└── README.md           # This file
```

### Security Considerations
- Change default passwords in production
- Use HTTPS in production environment
- Regularly update dependencies
- Monitor security logs
- Implement additional rate limiting at network level
- Consider implementing CAPTCHA for repeated failures

## Production Deployment

### Additional Security Measures
- Use reverse proxy (nginx/Apache)
- Implement SSL/TLS certificates
- Set up database replication
- Configure log rotation
- Implement backup strategies
- Use environment-specific configurations
- Set up monitoring and alerting

### Performance Optimization
- Database indexing on frequently queried columns
- Connection pooling for database
- Caching for static content
- Load balancing for multiple instances

## Support

For technical support or questions about the Communication_LTD Secured Information System, please refer to the system documentation or contact the development team.
