package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads the configuration from the given file path.
// If the file does not exist, it creates a default configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, create a default one
			cfg := DefaultConfig()
			if err := Save(path, cfg); err != nil {
				return nil, err
			}
			return cfg, nil
		}
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Save writes the configuration to the given file path.
func Save(path string, cfg *Config) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create config file: %v", err)
	}
	defer f.Close()

	encoder := yaml.NewEncoder(f)
	encoder.SetIndent(2)

	if err := encoder.Encode(cfg); err != nil {
		return fmt.Errorf("failed to encode config: %v", err)
	}

	return nil
}

// SaveDefaultConfig saves the default configuration to a file
func SaveDefaultConfig(path string) error {
	cfg := DefaultConfig()
	return Save(path, cfg)
}
