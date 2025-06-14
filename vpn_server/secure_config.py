import base64
import json
from typing import Optional
from cryptography.fernet import Fernet
import os

class SecureConfig:
    """
    Python implementation of Android Configuration class for secure storage
    Handles encrypted configuration persistence
    """
    
    def __init__(self, config_path: str, key: bytes):
        """
        Initialize secure configuration handler
        
        Args:
            config_path: Path to config file
            key: Encryption key (32 bytes)
        """
        self.config_path = config_path
        self.cipher = Fernet(key)
        self.raw_data = ""
        
        # Load existing config if available
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                self.raw_data = f.read()
    
    def get_bytes(self) -> Optional[bytes]:
        """Get decrypted config as bytes"""
        return self._decode_to_bytes(self.raw_data)
    
    def encode_to_base64(self, data: bytes) -> str:
        """Encrypt and encode data to base64"""
        try:
            encrypted = self.cipher.encrypt(data)
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            return ""
    
    def _decode_to_bytes(self, data: str) -> Optional[bytes]:
        """Decode base64 and decrypt data"""
        try:
            decoded = base64.b64decode(data)
            return self.cipher.decrypt(decoded)
        except Exception:
            return None
    
    def reset_config(self) -> None:
        """Clear configuration"""
        self.save_local("")
    
    def save_local(self, data: str) -> None:
        """Save encrypted config to file"""
        self.raw_data = data
        with open(self.config_path, 'w') as f:
            f.write(data)
    
    # Helper methods for JSON configs
    def save_config(self, config: dict) -> None:
        """Save dictionary config as encrypted JSON"""
        json_data = json.dumps(config).encode('utf-8')
        self.save_local(self.encode_to_base64(json_data))
    
    def load_config(self) -> Optional[dict]:
        """Load and decrypt JSON config"""
        data = self.get_bytes()
        if data:
            return json.loads(data.decode('utf-8'))
        return None
