package config

import (
	"encoding/json"
	"os"
)

// Config defines the server configuration structure
type Config struct {
	Server     string `json:"server"`      // Server address
	ServerPort int    `json:"server_port"` // Server port
	LocalPort  int    `json:"local_port"`  // Local port (client only)
	Method     string `json:"method"`      // Encryption method
	Password   string `json:"password"`    // Password
	LogLevel   string `json:"log_level"`   // Log level
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
