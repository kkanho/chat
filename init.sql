-- Use the specified database (Replace 'chatdb' with your actual database name if different)
USE chatdb;

-- Drop tables if they already exist (to avoid conflicts during development/testing)
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS users;

-- Create 'users' table
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    hashed_password VARCHAR(255) NOT NULL,
    password_salt VARCHAR(255) NOT NULL,
    twofa_key VARCHAR(255) NOT NULL,
    hashed_phrase VARCHAR(255) NOT NULL,
    public_key VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create 'messages' table
CREATE TABLE messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    message_text TEXT NOT NULL,
    iv VARCHAR(256),
    signature VARCHAR(512),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(user_id),
    FOREIGN KEY (receiver_id) REFERENCES users(user_id)
);

-- Optionally, insert some initial data for testing
INSERT INTO users (username, hashed_password, password_salt, twofa_key, hashed_phrase, public_key) VALUES ('Alice', '$2b$15$08JAbLHJDYavJPYicU73zu1KhfAV.B3RSmo5E6Bka2tnm.NC/BYnW', '$2b$15$08JAbLHJDYavJPYicU73zu', 'ISSIZL2SWHM5UYH2', 'd13ccecc083b425d9853d8d1c7ce9d676f7df2ba5c2691bc5d8da87325d4b267', '');
INSERT INTO users (username, hashed_password, password_salt, twofa_key, hashed_phrase, public_key) VALUES ('Bob', '$2b$15$HFR7t07VMpV7eF.78tauDOPJW5jqNXH7XNFMY9G76bnXgMyUZk3oK', '$2b$15$HFR7t07VMpV7eF.78tauDO', 'ISSIZL2SWHM5UYH2', 'd13ccecc083b425d9853d8d1c7ce9d676f7df2ba5c2691bc5d8da87325d4b267', '');
INSERT INTO users (username, hashed_password, password_salt, twofa_key, hashed_phrase, public_key) VALUES ('Kit', '$2b$15$08JAbLHJDYavJPYicU73zu1KhfAV.B3RSmo5E6Bka2tnm.NC/BYnW', '$2b$15$08JAbLHJDYavJPYicU73zu', 'ISSIZL2SWHM5UYH2', 'd13ccecc083b425d9853d8d1c7ce9d676f7df2ba5c2691bc5d8da87325d4b267', '');
INSERT INTO users (username, hashed_password, password_salt, twofa_key, hashed_phrase, public_key) VALUES ('William', '$2b$15$HFR7t07VMpV7eF.78tauDOPJW5jqNXH7XNFMY9G76bnXgMyUZk3oK', '$2b$15$HFR7t07VMpV7eF.78tauDO', 'ISSIZL2SWHM5UYH2', 'd13ccecc083b425d9853d8d1c7ce9d676f7df2ba5c2691bc5d8da87325d4b267', '');