package database

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"jx2-paysys/internal/config"
)

// AccountInfo represents the full account structure from jx2_paysys.sql
type AccountInfo struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	SecPassword string `json:"secpassword"`
	Active      int    `json:"active"`
	Locked      int    `json:"locked"`
	NewLocked   int    `json:"newlocked"`
	TryToHack   int    `json:"trytohack"`
	TryToCard   int    `json:"trytocard"`
	Coin        int64  `json:"coin"`
	TestCoin    int    `json:"testcoin"`
	Email       string `json:"email"`
}

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

// AccountLogin verifies account credentials using the real JX2 schema
func (c *Connection) AccountLogin(username, password string) (bool, error) {
	var count int
	// Use the real table name 'account' (singular) and check both active status and not locked
	query := "SELECT COUNT(*) FROM account WHERE username = ? AND password = ? AND active = 1 AND locked = 0"
	err := c.db.QueryRow(query, username, password).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to query account: %w", err)
	}
	return count > 0, nil
}

// GetAccountState gets the account state (using locked field from real schema)
func (c *Connection) GetAccountState(username string) (int, error) {
	var locked int
	query := "SELECT locked FROM account WHERE username = ?"
	err := c.db.QueryRow(query, username).Scan(&locked)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("account not found")
		}
		return 0, fmt.Errorf("failed to get account state: %w", err)
	}
	return locked, nil
}

// UpdateAccountState updates the account locked state
func (c *Connection) UpdateAccountState(username string, locked int) error {
	query := "UPDATE account SET locked = ? WHERE username = ?"
	_, err := c.db.Exec(query, locked, username)
	if err != nil {
		return fmt.Errorf("failed to update account state: %w", err)
	}
	return nil
}

// GetAccountInfo gets comprehensive account information
func (c *Connection) GetAccountInfo(username string) (*AccountInfo, error) {
	var acc AccountInfo
	query := `SELECT id, username, password, secpassword, active, locked, newlocked, 
			         trytohack, trytocard, coin, testcoin, email 
			  FROM account WHERE username = ?`
	err := c.db.QueryRow(query, username).Scan(
		&acc.ID, &acc.Username, &acc.Password, &acc.SecPassword,
		&acc.Active, &acc.Locked, &acc.NewLocked, &acc.TryToHack,
		&acc.TryToCard, &acc.Coin, &acc.TestCoin, &acc.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("account not found")
		}
		return nil, fmt.Errorf("failed to get account info: %w", err)
	}
	return &acc, nil
}

// UpdateLastLoginIP updates the last login IP for an account
func (c *Connection) UpdateLastLoginIP(username string, ip uint32) error {
	query := "UPDATE account SET LastLoginIP = ? WHERE username = ?"
	_, err := c.db.Exec(query, ip, username)
	if err != nil {
		return fmt.Errorf("failed to update last login IP: %w", err)
	}
	return nil
}

// GetCoinBalance gets the coin balance for an account
func (c *Connection) GetCoinBalance(username string) (int64, error) {
	var coin int64
	query := "SELECT coin FROM account WHERE username = ?"
	err := c.db.QueryRow(query, username).Scan(&coin)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("account not found")
		}
		return 0, fmt.Errorf("failed to get coin balance: %w", err)
	}
	return coin, nil
}

// UpdateCoinBalance updates the coin balance for an account
func (c *Connection) UpdateCoinBalance(username string, amount int64, updateType uint8) error {
	var query string
	switch updateType {
	case 0: // Set
		query = "UPDATE account SET coin = ? WHERE username = ?"
	case 1: // Add
		query = "UPDATE account SET coin = coin + ? WHERE username = ?"
	case 2: // Subtract
		query = "UPDATE account SET coin = coin - ? WHERE username = ?"
	default:
		return fmt.Errorf("invalid update type: %d", updateType)
	}
	
	_, err := c.db.Exec(query, amount, username)
	if err != nil {
		return fmt.Errorf("failed to update coin balance: %w", err)
	}
	return nil
}

// ChangePassword updates the password for an account
func (c *Connection) ChangePassword(username, oldPassword, newPassword string) error {
	// First verify the old password
	isValid, err := c.AccountLogin(username, oldPassword)
	if err != nil {
		return fmt.Errorf("failed to verify old password: %w", err)
	}
	if !isValid {
		return fmt.Errorf("invalid old password")
	}
	
	// Update to new password
	query := "UPDATE account SET password = ? WHERE username = ?"
	_, err = c.db.Exec(query, newPassword, username)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	return nil
}

// InitializeSchema creates basic database tables if they don't exist
// Note: For production use, import the jx2_paysys.sql file instead
func (c *Connection) InitializeSchema() error {
	// Check if account table already exists (from jx2_paysys.sql)
	var exists bool
	err := c.db.QueryRow("SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'account'").Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check table existence: %w", err)
	}
	
	if exists {
		// Table already exists, likely from jx2_paysys.sql import
		return nil
	}
	
	// Create minimal schema for testing (use jx2_paysys.sql for production)
	queries := []string{
		`CREATE TABLE IF NOT EXISTS account (
			id int(11) NOT NULL auto_increment,
			username varchar(32) NOT NULL,
			secpassword varchar(64) NOT NULL,
			password varchar(64) NOT NULL,
			rowpass varchar(32) default '1',
			trytocard int(1) NOT NULL default '0',
			changepwdret int(1) NOT NULL default '0',
			active int(1) NOT NULL default '1',
			LockPassword int(11) NOT NULL default '0',
			trytohack int(1) NOT NULL default '0',
			newlocked int(1) NOT NULL default '0',
			locked int(1) NOT NULL default '0',
			LastLoginIP int(11) NOT NULL default '0',
			PasspodMode int(11) NOT NULL default '0',
			email varchar(64) NOT NULL default 'admin@jx2.com',
			cmnd int(9) NOT NULL default '123456780',
			coin int(20) NOT NULL default '0',
			testcoin int(11) NOT NULL default '9999999',
			PRIMARY KEY (id),
			UNIQUE KEY u (username)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8`,
	}

	for _, query := range queries {
		if _, err := c.db.Exec(query); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	return nil
}