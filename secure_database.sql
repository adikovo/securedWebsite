-- Communication_LTD Secured Database Setup
-- This script creates the complete database structure for the secured version
-- of the Communication_LTD Information System

-- Create the main database
CREATE DATABASE IF NOT EXISTS communication_ltd_secured;
USE communication_ltd_secured;

-- Users table - stores user authentication and account information
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,                    
    username VARCHAR(255) UNIQUE NOT NULL,                
    password VARCHAR(255) NOT NULL,                       
    password_salt VARCHAR(255) NOT NULL,                  
    email VARCHAR(255) NOT NULL,                          
    is_locked BOOLEAN DEFAULT FALSE,                      
    lockout_until DATETIME,                               
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP        
);

-- Password history table - tracks previous passwords to prevent reuse
CREATE TABLE IF NOT EXISTS password_history (
    id INT PRIMARY KEY AUTO_INCREMENT,                    
    user_id INT NOT NULL,                                 
    password_hash VARCHAR(255) NOT NULL,                  
    password_salt VARCHAR(255) NOT NULL,                  
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,       
    FOREIGN KEY (user_id) REFERENCES users(id)            
);

-- Login attempts table - tracks login attempts for security monitoring
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT PRIMARY KEY AUTO_INCREMENT,                    
    user_id INT NOT NULL,                                 
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,     
    ip_address VARCHAR(45),                               
    FOREIGN KEY (user_id) REFERENCES users(id)            
);

-- Password reset tokens table - manages secure password reset process
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,                   
    user_id INT NOT NULL,                                
    token VARCHAR(255) NOT NULL,                         
    expires_at TIMESTAMP NOT NULL,                       
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,      
    FOREIGN KEY (user_id) REFERENCES users(id)           
);

-- Customers table - stores customer information for the business system
CREATE TABLE IF NOT EXISTS customers (
    id INT PRIMARY KEY AUTO_INCREMENT,                    
    name VARCHAR(255) NOT NULL,                           
    email VARCHAR(255),                                   
    address VARCHAR(255),                                 
    package_type VARCHAR(255)                             
); 