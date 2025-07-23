package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config represents the entire configuration
type Config struct {
	Paysys   PaysysConfig
	Database DatabaseConfig
}

// PaysysConfig represents paysys server configuration
type PaysysConfig struct {
	IP               string
	Port             int
	PingCycle        int
	InternalIPMask   string
	LocalIP          string
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	IP       string
	Port     int
	UserName string
	Password string
	DBName   string
}

// LoadConfig loads configuration from INI file
func LoadConfig(filename string) (*Config, error) {
	content, err := readFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := &Config{}
	err = parseINI(content, config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return config, nil
}

func readFile(filename string) (string, error) {
	// Simple file reading implementation
	// In production, you'd use ioutil.ReadFile or os.ReadFile
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	content := make([]byte, 0, 1024)
	buffer := make([]byte, 512)
	for {
		n, err := file.Read(buffer)
		if n > 0 {
			content = append(content, buffer[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return "", err
		}
	}
	return string(content), nil
}

func parseINI(content string, config *Config) error {
	lines := strings.Split(content, "\n")
	var currentSection string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			err := setConfigValue(config, currentSection, key, value)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func setConfigValue(config *Config, section, key, value string) error {
	switch section {
	case "Paysys":
		switch key {
		case "IP":
			config.Paysys.IP = value
		case "Port":
			port, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid port value: %s", value)
			}
			config.Paysys.Port = port
		case "PingCycle":
			cycle, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid ping cycle value: %s", value)
			}
			config.Paysys.PingCycle = cycle
		case "InternalIPMask":
			config.Paysys.InternalIPMask = value
		case "LocalIP":
			config.Paysys.LocalIP = value
		}
	case "Database":
		switch key {
		case "IP":
			config.Database.IP = value
		case "Port":
			port, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid database port value: %s", value)
			}
			config.Database.Port = port
		case "UserName":
			config.Database.UserName = value
		case "Password":
			config.Database.Password = value
		case "DBName":
			config.Database.DBName = value
		}
	}
	return nil
}