-- JX2 Paysys Database Schema
-- This recreates the database structure from the original paysys

CREATE DATABASE IF NOT EXISTS jx2_paysys;
USE jx2_paysys;

-- Account table for user authentication
CREATE TABLE IF NOT EXISTS accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    state INT DEFAULT 0 COMMENT '0=normal, 1=banned, 2=suspended',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username)
);

-- Login sessions for tracking active connections
CREATE TABLE IF NOT EXISTS login_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    logout_time TIMESTAMP NULL,
    INDEX idx_username (username),
    INDEX idx_session_id (session_id)
);

-- Bishop servers for managing game server connections
CREATE TABLE IF NOT EXISTS bishop_servers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_id VARCHAR(255) UNIQUE NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    port INT NOT NULL,
    status INT DEFAULT 1 COMMENT '0=offline, 1=online',
    last_ping TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_server_id (server_id)
);

-- Character charges and payments
CREATE TABLE IF NOT EXISTS account_charges (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    charge_type INT NOT NULL COMMENT '1=item_buy, 2=item_use, 3=exchange',
    amount DECIMAL(10,2) NOT NULL,
    item_id INT NULL,
    transaction_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_transaction_id (transaction_id)
);

-- Insert test data for development
INSERT INTO accounts (username, password, state) VALUES 
('testuser', 'testpass', 0),
('admin', 'admin123', 0),
('banned_user', 'password', 1)
ON DUPLICATE KEY UPDATE username=username;

INSERT INTO bishop_servers (server_id, ip_address, port, status) VALUES
('BISHOP001', '127.0.0.1', 9999, 1),
('BISHOP002', '192.168.1.100', 9999, 1)
ON DUPLICATE KEY UPDATE server_id=server_id;