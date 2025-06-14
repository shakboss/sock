package config

type Config struct {
	Server ServerConfig `yaml:"server"`
	SSH    SSHConfig    `yaml:"ssh"`
	SOCKS5 SOCKS5Config `yaml:"socks5"`
	DNS    DNSConfig    `yaml:"dns"`
}

type ServerConfig struct {
	ListenAddress string `yaml:"listen_address"`
	LogLevel      string `yaml:"log_level"`
}

type SSHConfig struct {
	Enabled      bool   `yaml:"enabled"`
	ListenAddr   string `yaml:"listen_addr"`
	HostKeyPath  string `yaml:"host_key_path"`
	Banner       string `yaml:"banner"`
	MaxAuthTries int    `yaml:"max_auth_tries"`
}

type SOCKS5Config struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Auth       struct {
		Enabled  bool   `yaml:"enabled"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"auth"`
}

type DNSConfig struct {
	Enabled    bool     `yaml:"enabled"`
	ListenAddr string   `yaml:"listen_addr"`
	Upstreams  []string `yaml:"upstreams"`
	CacheSize  int      `yaml:"cache_size"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddress: ":8080",
			LogLevel:      "info",
		},
		SSH: SSHConfig{
			Enabled:      true,
			ListenAddr:   ":2082",
			HostKeyPath:  "ssh_host_key",
			Banner:       "SSH-2.0-SocksIP_Server",
			MaxAuthTries: 3,
		},
		SOCKS5: SOCKS5Config{
			Enabled:    true,
			ListenAddr: ":8989",
			Auth: struct {
				Enabled  bool   `yaml:"enabled"`
				Username string `yaml:"username"`
				Password string `yaml:"password"`
			}{
				Enabled: false,
			},
		},
		DNS: DNSConfig{
			Enabled:    true,
			ListenAddr: ":53",
			Upstreams: []string{
				"1.1.1.1:53",
				"8.8.8.8:53",
			},
			CacheSize: 1000,
		},
	}
}
