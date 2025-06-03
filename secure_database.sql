-- Communication_LTD Secured Database Setup
-- This script creates the complete database structure for the secured version
-- of the Communication_LTD Information System

-- Create the main database
CREATE DATABASE IF NOT EXISTS communication_ltd_secured;
USE communication_ltd_secured;

-- Users table - stores user authentication and account information
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,                    -- Unique user identifier
    username VARCHAR(255) UNIQUE NOT NULL,                -- Username (must be unique)
    password VARCHAR(255) NOT NULL,                       -- Hashed password using PBKDF2
    password_salt VARCHAR(255) NOT NULL,                  -- Salt used for password hashing
    email VARCHAR(255) NOT NULL,                          -- User email address
    is_locked BOOLEAN DEFAULT FALSE,                      -- Account lockout status
    lockout_until DATETIME,                               -- Lockout expiration time
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP        -- Account creation timestamp
);

-- Password history table - tracks previous passwords to prevent reuse
CREATE TABLE IF NOT EXISTS password_history (
    id INT PRIMARY KEY AUTO_INCREMENT,                    -- Unique history record ID
    user_id INT NOT NULL,                                 -- Reference to users table
    password_hash VARCHAR(255) NOT NULL,                  -- Previous password hash
    password_salt VARCHAR(255) NOT NULL,                  -- Previous password salt
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,       -- When password was used
    FOREIGN KEY (user_id) REFERENCES users(id)            -- Foreign key constraint
);

-- Login attempts table - tracks login attempts for security monitoring
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT PRIMARY KEY AUTO_INCREMENT,                    -- Unique attempt ID
    user_id INT NOT NULL,                                 -- Reference to users table
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,     -- When login was attempted
    ip_address VARCHAR(45),                               -- IP address of attempt (supports IPv6)
    FOREIGN KEY (user_id) REFERENCES users(id)            -- Foreign key constraint
);

-- Password reset tokens table - manages secure password reset process
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,                    -- Unique token ID
    user_id INT NOT NULL,                                 -- Reference to users table
    token VARCHAR(255) NOT NULL,                          -- Secure reset token (cryptographically generated)
    expires_at TIMESTAMP NOT NULL,                        -- Token expiration time (1 hour)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,       -- Token creation time
    FOREIGN KEY (user_id) REFERENCES users(id)            -- Foreign key constraint
);

-- Customers table - stores customer information for the business system
CREATE TABLE IF NOT EXISTS customers (
    id INT PRIMARY KEY AUTO_INCREMENT,                    -- Unique customer ID
    name VARCHAR(255) NOT NULL,                           -- Customer full name
    email VARCHAR(255),                                   -- Customer email address
    address VARCHAR(255),                                 -- Customer physical address
    package_type VARCHAR(255)                             -- Service package type
); 