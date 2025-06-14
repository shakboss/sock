"""
Comprehensive Test Suite for VPN Server
"""
import os
import pytest
import asyncio
from config import ServerConfig
from secure_config import SecureConfig
from tunnel_handler import TunnelHandler

# Test Configurations
TEST_KEY = b'TEST_KEY_TEST_KEY_TEST_KEY_TEST_KEY_'
CONFIG_FILES = [
    'configs/udp_config.json',
    'configs/request_config.json',
    'configs/dns_config.json',
    'configs/websocket_config.json',
    'configs/ssh_config.json',
    'configs/single_request_config.json'
]

@pytest.mark.parametrize("config_file", CONFIG_FILES)
def test_config_loading(config_file):
    """Test loading all configuration files"""
    config = ServerConfig.load(config_file)
    assert config is not None
    assert config.validate()

@pytest.mark.parametrize("config_file", CONFIG_FILES)
def test_secure_config(config_file, tmp_path):
    """Test encryption/decryption roundtrip"""
    config = ServerConfig.load(config_file)
    secure_file = tmp_path / "secure_config.bin"
    
    # Test encryption
    secure = SecureConfig(TEST_KEY)
    encrypted = secure.encrypt_config(config)
    assert encrypted is not None
    
    # Test decryption
    decrypted = secure.decrypt_config(encrypted)
    assert decrypted.to_dict() == config.to_dict()

@pytest.mark.asyncio
@pytest.mark.parametrize("tunnel_type", [0, 1, 2, 3, 4, 5])
async def test_tunnel_initialization(tunnel_type):
    """Test tunnel handler initialization"""
    config = ServerConfig(tunnel_type=tunnel_type)
    handler = TunnelHandler(config)
    
    # Start and immediately stop tunnel
    task = asyncio.create_task(handler.start())
    await asyncio.sleep(0.1)  # Let it initialize
    handler.stop()
    
    # Cleanup
    await task
    assert True  # If we got here without errors

def test_field_validation():
    """Test config field validation"""
    # Test valid config
    valid_config = ServerConfig(
        tunnel_type=0,
        start_port=10000,
        end_port=10010,
        sender_count=10,
        receiver_count=5
    )
    assert valid_config.validate()
    
    # Test invalid config
    invalid_config = ServerConfig(
        tunnel_type=99,
        start_port=0,
        end_port=70000,
        sender_count=300,
        receiver_count=0
    )
    with pytest.raises(ValueError):
        invalid_config.validate()

if __name__ == "__main__":
    pytest.main(["-v", "--cov=.", "--cov-report=html"])
