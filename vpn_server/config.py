"""
Server configuration equivalent to Android's SerSocksIP
"""
from dataclasses import dataclass
from typing import Optional, Dict
import copy

@dataclass
class ServerConfig:
    """
    Comprehensive VPN server configuration with validation
    
    Attributes mirroring Android SerSocksIP but with Python conventions
    """
    # Network configuration
    protocol: str = ""
    server: str = ""
    free_server: str = ""
    proxy_host_port: str = ""
    listen_port: str = "8000"
    
    # Tunnel types
    tunnel_type: int = 0  # 0=UDP, 1=TUN, 2=DNS, 3=SSH, 4=UDP Request Tunnel, 5=UDP Request Tunnel (alternative)
    ssh_transport_type: int = 0
    dns_tunnel_type: int = 0
    
    # Authentication
    password: str = ""
    free_password: str = ""
    ssh_password: str = ""
    ssh_username: str = ""
    pub_key: str = ""
    free_pub_key: str = ""
    
    # DNS configuration
    dns_resolver: int = 0  # 0=UDP, 1=DoT, 2=DoH
    dns_udp: str = "8.8.8.8:53"
    dns_dot: str = "8.8.8.8:853"
    dns_doh: str = "https://dns.google/dns-query"
    
    # Security flags
    lock_all: bool = False
    lock_password: bool = False
    lock_server: bool = False
    lock_proxy: bool = False
    start_with_hwid: bool = False
    
    # Advanced settings
    hwid: str = ""
    expiration: int = 0
    enable_binding: bool = False
    
    # UDP Request Tunnel specific
    start_port: int = 10000  # 1-65535
    end_port: int = 10010    # 1-65535
    sender_count: int = 10   # 1-255
    receiver_count: int = 5  # 1-255
    
    # Additional fields from SerSocksIP
    TypeSSHTransport: int = 0
    SSHPayload: str = ""
    SNIPayload: str = ""
    DNSTType: int = 0
    DNSResolver: int = 0
    DNSudp: str = ""
    DNSdot: str = ""
    DNSdotR: str = ""
    DNSdoh: str = ""
    DNSdohR: str = ""
    enableHTTPWS: bool = False
    CDNHost: str = ""
    CDNHostAddr: str = ""
    CDNTargetADDR: str = ""
    
    def validate(self) -> bool:
        """Validate configuration values"""
        if self.tunnel_type not in (0, 1, 2, 3, 4, 5):
            raise ValueError("Invalid tunnel type")
            
        if self.tunnel_type == 1:  # TUN
            pass
        elif self.tunnel_type == 4 or self.tunnel_type == 5:  # UDP Request Tunnel
            if not (1 <= self.start_port <= 65535):
                raise ValueError("Start port must be 1-65535")
            if not (1 <= self.end_port <= 65535):
                raise ValueError("End port must be 1-65535")
            if not (1 <= self.sender_count <= 255):
                raise ValueError("Sender count must be 1-255")
            if not (1 <= self.receiver_count <= 255):
                raise ValueError("Receiver count must be 1-255")
                
        if self.dns_resolver not in (0, 1, 2):
            raise ValueError("Invalid DNS resolver type")
            
        if self.DNSTType not in [0, 1, 2]:
            raise ValueError("Invalid DNSTType")
        if self.DNSResolver not in [0, 1]:
            raise ValueError("Invalid DNSResolver")
        
        return True
    
    def clone(self) -> 'ServerConfig':
        """Create a deep copy of the configuration"""
        return copy.deepcopy(self)
    
    def to_dict(self) -> Dict:
        """Convert configuration to dictionary"""
        return {k: v for k, v in self.__dict__.items() 
                if not k.startswith('_')}
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ServerConfig':
        """Create config from dictionary"""
        return cls(**data)
    
    @classmethod
    def from_secure_file(cls, config_path: str, key: bytes) -> 'ServerConfig':
        """Load config from encrypted file"""
        from secure_config import SecureConfig
        secure = SecureConfig(config_path, key)
        data = secure.load_config()
        if not data:
            raise ValueError("Failed to decrypt config")
        return cls(**data)
    
    def to_secure_file(self, config_path: str, key: bytes) -> None:
        """Save config to encrypted file"""
        from secure_config import SecureConfig
        secure = SecureConfig(config_path, key)
        secure.save_config(asdict(self))
