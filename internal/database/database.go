package database

import (
	"context"
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

// CharacterInfo represents character data structure (based on JX1 analysis)
type CharacterInfo struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`  // Account owner
	Level    int    `json:"level"`
	Class    int    `json:"class"`
	Gender   int    `json:"gender"`
	MapID    int    `json:"map_id"`
	X        int    `json:"x"`
	Y        int    `json:"y"`
	Created  string `json:"created"`
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

// GetCharacters retrieves all characters for a given username
func (c *Connection) GetCharacters(ctx context.Context, username string) ([]CharacterInfo, error) {
	query := `SELECT id, name, username, level, class, gender, map_id, x, y, created 
			  FROM characters WHERE username = ? ORDER BY created ASC`
	
	rows, err := c.db.QueryContext(ctx, query, username)
	if err != nil {
		return nil, fmt.Errorf("failed to query characters: %w", err)
	}
	defer rows.Close()
	
	var characters []CharacterInfo
	for rows.Next() {
		var char CharacterInfo
		err := rows.Scan(&char.ID, &char.Name, &char.Username, &char.Level, 
						 &char.Class, &char.Gender, &char.MapID, &char.X, &char.Y, &char.Created)
		if err != nil {
			return nil, fmt.Errorf("failed to scan character: %w", err)
		}
		characters = append(characters, char)
	}
	
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating characters: %w", err)
	}
	
	return characters, nil
}

// CreateCharacter creates a new character for a user
func (c *Connection) CreateCharacter(ctx context.Context, username, charName string, class, gender int) error {
	// Check if character name already exists
	var count int
	checkQuery := "SELECT COUNT(*) FROM characters WHERE name = ?"
	err := c.db.QueryRowContext(ctx, checkQuery, charName).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check character name: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("character name already exists")
	}
	
	// Check character limit per account (max 8 characters)
	charCountQuery := "SELECT COUNT(*) FROM characters WHERE username = ?"
	err = c.db.QueryRowContext(ctx, charCountQuery, username).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check character count: %w", err)
	}
	if count >= 8 {
		return fmt.Errorf("character limit reached")
	}
	
	// Create the character with default values
	insertQuery := `INSERT INTO characters (name, username, level, class, gender, map_id, x, y, created) 
				   VALUES (?, ?, 1, ?, ?, 1, 100, 100, NOW())`
	
	_, err = c.db.ExecContext(ctx, insertQuery, charName, username, class, gender)
	if err != nil {
		return fmt.Errorf("failed to create character: %w", err)
	}
	
	return nil
}

// DeleteCharacter deletes a character by name
func (c *Connection) DeleteCharacter(ctx context.Context, charName string) error {
	query := "DELETE FROM characters WHERE name = ?"
	result, err := c.db.ExecContext(ctx, query, charName)
	if err != nil {
		return fmt.Errorf("failed to delete character: %w", err)
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}
	
	if rowsAffected == 0 {
		return fmt.Errorf("character not found")
	}
	
	return nil
}

// GetCharacter gets a specific character by name
func (c *Connection) GetCharacter(ctx context.Context, charName string) (*CharacterInfo, error) {
	var char CharacterInfo
	query := `SELECT id, name, username, level, class, gender, map_id, x, y, created 
			  FROM characters WHERE name = ?`
	
	err := c.db.QueryRowContext(ctx, query, charName).Scan(
		&char.ID, &char.Name, &char.Username, &char.Level, 
		&char.Class, &char.Gender, &char.MapID, &char.X, &char.Y, &char.Created)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("character not found")
		}
		return nil, fmt.Errorf("failed to get character: %w", err)
	}
	
	return &char, nil
}

