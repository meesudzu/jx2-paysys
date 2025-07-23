package database

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"jx2-paysys/internal/config"
)

// Connection wraps the database connection
type Connection struct {
	db *sql.DB
}

// NewConnection creates a new database connection
func NewConnection(cfg config.DatabaseConfig) (*Connection, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.UserName, cfg.Password, cfg.IP, cfg.Port, cfg.DBName)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Connection{db: db}, nil
}

// Close closes the database connection
func (c *Connection) Close() error {
	return c.db.Close()
}

// AccountLogin verifies account credentials
func (c *Connection) AccountLogin(username, password string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM accounts WHERE username = ? AND password = ?"
	err := c.db.QueryRow(query, username, password).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to query account: %w", err)
	}
	return count > 0, nil
}

// GetAccountState gets the account state
func (c *Connection) GetAccountState(username string) (int, error) {
	var state int
	query := "SELECT state FROM accounts WHERE username = ?"
	err := c.db.QueryRow(query, username).Scan(&state)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("account not found")
		}
		return 0, fmt.Errorf("failed to get account state: %w", err)
	}
	return state, nil
}

// UpdateAccountState updates the account state
func (c *Connection) UpdateAccountState(username string, state int) error {
	query := "UPDATE accounts SET state = ? WHERE username = ?"
	_, err := c.db.Exec(query, state, username)
	if err != nil {
		return fmt.Errorf("failed to update account state: %w", err)
	}
	return nil
}

// InitializeSchema creates the necessary database tables
func (c *Connection) InitializeSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS accounts (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			state INT DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS login_sessions (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(255) NOT NULL,
			session_id VARCHAR(255) NOT NULL,
			ip_address VARCHAR(45),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_username (username),
			INDEX idx_session_id (session_id)
		)`,
	}

	for _, query := range queries {
		if _, err := c.db.Exec(query); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	return nil
}