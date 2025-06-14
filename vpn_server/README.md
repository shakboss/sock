# VPN Server Implementation

Python server matching the Java VPN client architecture from the analyzed codebase.

## Features
- JWT authentication (matching client's auth system)
- PBKDF2-HMAC-SHA512 key derivation (matches Java implementation)
- HMAC message authentication
- AES-256 encryption
- FastAPI REST endpoints

## Setup
1. Install requirements:
```
pip install -r requirements.txt
```

2. Run server:
```
python main.py
```

## Endpoints
- POST `/register` - User registration
- POST `/token` - Get authentication token
- GET `/config` - Get VPN configuration

## Tunneling Architecture

1. **UDP Tunneling**
   - Encrypted UDP packets
   - HMAC verification
   - Port 1194 default

2. **TUN Tunneling**
   - Virtual network interface
   - Packet-level encryption
   - MTU 1500

3. **DNS Tunneling**
   - Encrypted DNS queries
   - Local cache
   - Fallback to configured DNS servers

### Security Features
- All tunnels use:
  - AES-256 encryption
  - SHA-512 HMAC
  - Session keys derived via PBKDF2

## Protocol Selection
Configure via:
```json
{
  "protocol": "udp" // or "tun", "dns"
}
```

All protocols use the same:
- AES-256 encryption
- HMAC authentication
- PBKDF2 key derivation

## Security
- Uses same cryptographic primitives as Java client:
  - SHA-512 for hashing
  - PBKDF2 for key derivation
  - HMAC for message auth
  - AES for encryption

## Server Configuration

The `ServerConfig` class provides centralized configuration management similar to Android's `SerSocksIP`:

### Key Features:
- Structured configuration for all VPN parameters
- Type hints for better code completion
- `@dataclass` for automatic boilerplate code
- Deep copy support via `clone()` method

### Usage Example:
```python
from config import ServerConfig

# Create configuration
config = ServerConfig(
    tunnel_type=0,  # UDP
    server="vpn.example.com",
    password="secure123",
    enable_free_servers=False
)

# Clone configuration
config_copy = config.clone()
```

### Configuration Fields:
- **Network Settings**: `server`, `proxy_host_port`, `listen_port`
- **Security**: `password`, `pub_key`, `lock_password`
- **Tunnel Types**: `tunnel_type`, `dns_tunnel_type`, `ssh_transport_type`
- **DNS Settings**: `dns_resolver`, `dns_udp`, `dns_dot`, `dns_doh`
- **Advanced**: `hwid`, `cdn_host`, `expiration`, `enable_binding`

## Secure Configuration Storage

ServerConfig supports encrypted storage:

```python
from config import ServerConfig
from cryptography.fernet import Fernet

# Generate/store this key securely!
key = Fernet.generate_key()

# Save encrypted config
config = ServerConfig(tunnel_type=1, server="vpn.example.com")
config.to_secure_file("secure_config.bin", key)

# Load encrypted config 
loaded = ServerConfig.from_secure_file("secure_config.bin", key)
```

**Security Notes**:
- Uses AES-128-CBC encryption
- Configs are base64 encoded
- Key must be stored securely

## Tunnel Mode Configuration

Each tunnel mode requires specific configuration parameters:

### 1. UDP Tunnel (0)
```python
config = ServerConfig(
    tunnel_type=0,
    server="vpn.example.com:8000",
    password="secure123",
    enable_binding=True
)
```
**Required Fields**:
- `server`: VPN server address:port
- `password`: Authentication password

### 2. Request Tunnel (1)
```python
config = ServerConfig(
    tunnel_type=1,
    proxy_host_port="proxy.example.com:8080",
    payload="custom_payload",
    password="one",
    start_port=10000,  # 1-65535
    end_port=10010,    # 1-65535
    sender_count=10,   # 1-255
    receiver_count=5   # 1-255
)
```
**Required Fields**:
- `proxy_host_port`: Proxy server address
- `payload`: Custom request payload
- `start_port`: Starting port (1-65535)
- `end_port`: Ending port (1-65535)
- `sender_count`: Sender threads (1-255)
- `receiver_count`: Receiver threads (1-255)

### 3. DNS Tunnel (2)
```python
config = ServerConfig(
    tunnel_type=2,
    dns_resolver=1,  # 1=DoT
    dns_dot="dns.example.com:853",
    tunnel_domain="t.example.com"
)
```
**Required Fields**:
- `dns_resolver`: 0=UDP, 1=DoT, 2=DoH
- Corresponding DNS server field
- `tunnel_domain`: Tunnel domain name

### 4. Custom Websocket (3)
```python
config = ServerConfig(
    tunnel_type=3,
    server="ws.example.com",
    listen_port="8001",
    enable_http_ws=True
)
```
**Required Fields**:
- `server`: WebSocket server URL
- `listen_port`: Local listen port

### 5. Custom SSH (4)
```python
config = ServerConfig(
    tunnel_type=4,
    ssh_server="ssh.example.com:22",
    ssh_username="user",
    ssh_password="pass"
)
```
**Required Fields**:
- `ssh_server`: SSH server address:port
- `ssh_username`: SSH username
- `ssh_password`: SSH password

### 6. Single Request Tunnel (5)
```python
config = ServerConfig(
    tunnel_type=5,
    server="single.example.com",
    remote_udp_port=7300,
    udp_request_type=1
)
```
**Required Fields**:
- `server`: Target server
- `remote_udp_port`: UDP port for requests
- `udp_request_type`: Request protocol version

## Validation Rules
- Ports must be between 1-65535
- Counter values must be between 1-255
- Start port must be <= end port
- Configuration will raise ValueError if invalid

## Example Configuration Files

Example configs for each tunnel mode are available in `configs/` directory:

1. `udp_config.json` - UDP tunnel
2. `request_config.json` - Request tunnel
3. `dns_config.json` - DNS tunnel
4. `websocket_config.json` - WebSocket tunnel
5. `ssh_config.json` - SSH tunnel
6. `single_request_config.json` - Single request tunnel

To use:
```python
import json
from config import ServerConfig

with open('configs/udp_config.json') as f:
    config = ServerConfig(**json.load(f))
```

## Socksip Service Implementation

The server implements core VPN service functionality matching the Android `socksipService`:

### Key Features:
1. **Tunnel Management**
   - UDP and SSH tunnel support
   - Connection lifecycle control
   
2. **Network Configuration**
   - Route management
   - DNS server configuration
   - Bypass rules
   
3. **Status Monitoring**
   - Connection state tracking
   - Tunnel type reporting
   
### Configuration Options:
```json
{
  "tunnel_type": "udp|ssh",
  "primary_dns": "8.8.8.8",
  "secondary_dns": "8.8.4.4",
  "bypass_routes": ["192.168.1.0/24"]
}
```

Note: This is a server-side implementation and doesn't include Android-specific features.

## Action Handler Implementation

The server implements multi-action handling similar to `MultipleRunnableAction`:

### Supported Actions:
1. **Start SOCKS Server (0)**
   - Configures and starts SOCKS proxy
   - Handles different tunnel types
   - Manages credentials and payload

2. **Run Tunnel Binary (1)**
   - Configures network interfaces
   - Sets up SOCKS server address
   - Handles UDP forwarding if enabled

### Configuration Options:
```json
{
  "tunnel_type": 0,
  "server": "vpn.example.com",
  "password": "secure_password",
  "payload": "",
  "enable_udp": true
}
```

Note: This is a server-side implementation and doesn't include Android-specific features.

## UDP Request Handling

The server implements UDP request handling similar to the Android `UDPRequest` service but adapted for a server context.

### Key Features:
1. **Client Authentication**
   - Verify client credentials
   - Manage client sessions

2. **Packet Routing**
   - Route traffic based on client IP
   - Maintain virtual IP mappings

3. **Security**
   - HMAC verification for all packets
   - Encrypted communication
   - Session management

### Differences from Android Implementation:
- No Android-specific features (notifications, wake locks)
- Focused on server-side routing rather than device VPN
- Uses Python's asyncio for efficient network handling

### UDP Request Format
```json
{
  "packet_data": "base64_encoded_bytes",
  "source_ip": "client_ip",
  "source_port": 12345,
  "timestamp": "ISO8601",
  "protocol_version": 1
}
```

- `packet_data`: Encrypted UDP payload
- `source_ip`: Originating client IP
- `source_port`: Originating client port
- Uses current timestamp by default

## DNS Tunnel Implementation

The server implements DNS tunneling functionality similar to the Android `DNSTunnel` class:

### Features:
- Supports multiple DNS protocols:
  - UDP (default)
  - DNS-over-TLS (DoT)
  - DNS-over-HTTPS (DoH)
- Two operation modes:
  - SSH Tunnel Mode
  - VPN Mode
- Secure packet handling:
  - HMAC-SHA512 verification
  - Optional encryption

### Configuration Options:
```json
{
  "resolver_type": 0,  // 0=UDP, 1=DoT, 2=DoH
  "tunnel_type": 0,    // 0=VPN Mode, 1=SSH Tunnel Mode
  "udp_server": "8.8.8.8:53",
  "dot_server": "8.8.8.8:853",
  "doh_server": "https://dns.google/dns-query",
  "enable_udp": true,
  "bypass_apps": {"app1": true, "app2": false}
}
```

### Usage:
```python
dns_tunnel = DNSTunnel(config)
await dns_tunnel.start()  # Start tunnel
await dns_tunnel.handle_packet(packet)  # Process packet
await dns_tunnel.stop()  # Stop tunnel
```

Note: This is a server-side implementation and doesn't include Android-specific features like notifications or wake locks.
