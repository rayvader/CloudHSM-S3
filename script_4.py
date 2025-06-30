# Create the configuration manager and example files
config_manager_code = '''"""
Configuration Manager Module

This module handles configuration management for CloudHSM and AWS settings.
"""

import json
import configparser
import os
from typing import Dict, Any, Optional


class ConfigManager:
    """Manages configuration for CloudHSM and AWS settings."""
    
    def __init__(self, config_path: str = "config/cloudhsm_config.json"):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                # Create default configuration
                default_config = self._get_default_config()
                self._save_config(default_config)
                return default_config
        except Exception as e:
            print(f"Error loading config: {str(e)}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "cloudhsm": {
                "cluster_id": "cluster-12345678",
                "pkcs11_library_path": "/opt/cloudhsm/lib/libcloudhsm_pkcs11_standard.so",
                "crypto_user": "crypto-user",
                "crypto_password": "your-crypto-password"
            },
            "aws": {
                "region": "us-west-2",
                "s3_bucket": "your-test-bucket"
            },
            "encryption": {
                "key_label": "rsa-oaep-key",
                "key_size": 2048,
                "hash_algorithm": "SHA256",
                "mgf": "MGF1"
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            }
        }
    
    def _save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file."""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {str(e)}")
            return False
    
    def get_cloudhsm_config(self) -> Dict[str, Any]:
        """Get CloudHSM configuration."""
        return self.config.get("cloudhsm", {})
    
    def get_aws_config(self) -> Dict[str, Any]:
        """Get AWS configuration."""
        return self.config.get("aws", {})
    
    def get_encryption_config(self) -> Dict[str, Any]:
        """Get encryption configuration."""
        return self.config.get("encryption", {})
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration."""
        return self.config.get("logging", {})
    
    def update_config(self, section: str, key: str, value: Any) -> bool:
        """
        Update configuration value.
        
        Args:
            section: Configuration section
            key: Configuration key
            value: New value
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if section not in self.config:
                self.config[section] = {}
            
            self.config[section][key] = value
            return self._save_config(self.config)
        except Exception as e:
            print(f"Error updating config: {str(e)}")
            return False
    
    def get_config_value(self, section: str, key: str, default: Any = None) -> Any:
        """
        Get configuration value.
        
        Args:
            section: Configuration section
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        return self.config.get(section, {}).get(key, default)
'''

# Write the configuration manager to file
with open('config_manager.py', 'w') as f:
    f.write(config_manager_code)

# Create the main example script
main_example_code = '''#!/usr/bin/env python3
"""
Main Example Script for CloudHSM PKCS#11 with S3 Integration

This script demonstrates the complete workflow of:
1. Connecting to CloudHSM
2. Generating RSA key pairs
3. Encrypting files using RSA-OAEP
4. Uploading encrypted files to S3
5. Downloading and decrypting files from S3
"""

import os
import sys
import logging
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from cloudhsm_manager import CloudHSMManager
from s3_encryption import S3EncryptionManager
from crypto_utils import RSAOAEPCipher
from config_manager import ConfigManager


def setup_logging():
    """Setup logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def create_sample_files():
    """Create sample text files for testing."""
    sample_data_dir = Path("tests/sample_data")
    sample_data_dir.mkdir(parents=True, exist_ok=True)
    
    # Create sample files
    files = [
        ("test_file1.txt", "Hello CloudHSM!\\nThis is a test file for encryption.\\nIt contains multiple lines of text."),
        ("test_file2.txt", "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\\n" * 10),
        ("large_file.txt", "This is a larger file for testing hybrid encryption.\\n" * 1000)
    ]
    
    for filename, content in files:
        file_path = sample_data_dir / filename
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"✅ Created sample file: {file_path}")


def main():
    """Main demonstration function."""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    print("🔐 CloudHSM PKCS#11 with S3 Integration Demo")
    print("=" * 50)
    
    # Create sample files
    print("\\n📁 Creating sample files...")
    create_sample_files()
    
    # Initialize configuration
    print("\\n⚙️  Loading configuration...")
    config = ConfigManager()
    
    # Initialize CloudHSM manager
    print("\\n🔌 Connecting to CloudHSM...")
    hsm = CloudHSMManager()
    
    if not hsm.connect():
        print("❌ Failed to connect to CloudHSM. Please check your configuration.")
        return
    
    try:
        # Generate RSA key pair
        print("\\n🔑 Generating RSA key pair...")
        key_label = config.get_encryption_config()['key_label']
        key_size = config.get_encryption_config()['key_size']
        
        public_key, private_key = hsm.generate_rsa_keypair(
            key_size=key_size,
            label=key_label,
            extractable=False
        )
        
        if not public_key or not private_key:
            print("❌ Failed to generate key pair")
            return
        
        print(f"✅ Generated {key_size}-bit RSA key pair: {key_label}")
        
        # List all keys
        print("\\n📋 Listing all keys in CloudHSM...")
        keys = hsm.list_keys()
        for key_type, key_list in keys.items():
            print(f"  {key_type.capitalize()}: {len(key_list)} keys")
            for key in key_list[:3]:  # Show first 3 keys
                print(f"    - {key}")
        
        # Initialize S3 encryption manager
        print("\\n☁️  Initializing S3 encryption manager...")
        bucket_name = config.get_aws_config()['s3_bucket']
        s3_manager = S3EncryptionManager(
            bucket_name=bucket_name,
            hsm_manager=hsm,
            use_hybrid=True
        )
        
        # Test encryption and S3 upload
        print("\\n🔒 Testing encryption and S3 upload...")
        test_files = [
            "tests/sample_data/test_file1.txt",
            "tests/sample_data/test_file2.txt",
            "tests/sample_data/large_file.txt"
        ]
        
        for local_file in test_files:
            if os.path.exists(local_file):
                s3_key = f"encrypted/{os.path.basename(local_file)}"
                
                print(f"  📤 Uploading: {local_file} -> s3://{bucket_name}/{s3_key}")
                success = s3_manager.encrypt_and_upload(
                    local_file_path=local_file,
                    s3_key=s3_key,
                    public_key_label=key_label,
                    metadata={"source": "demo", "encrypted": "true"}
                )
                
                if success:
                    print(f"    ✅ Upload successful")
                else:
                    print(f"    ❌ Upload failed")
        
        # List encrypted files in S3
        print("\\n📂 Listing encrypted files in S3...")
        files_info = s3_manager.list_encrypted_files(prefix="encrypted/")
        print(f"  Found {files_info['file_count']} encrypted files:")
        for file_info in files_info['files']:
            print(f"    - {file_info['key']} ({file_info['original_size']} bytes, {file_info['encryption_method']})")
        
        # Test decryption and download
        print("\\n🔓 Testing decryption and download...")
        download_dir = Path("tests/decrypted")
        download_dir.mkdir(exist_ok=True)
        
        for file_info in files_info['files']:
            s3_key = file_info['key']
            local_file = download_dir / file_info['original_filename']
            
            print(f"  📥 Downloading: s3://{bucket_name}/{s3_key} -> {local_file}")
            success = s3_manager.download_and_decrypt(
                s3_key=s3_key,
                local_file_path=str(local_file),
                private_key_label=key_label
            )
            
            if success:
                print(f"    ✅ Download and decryption successful")
                # Verify file content
                if local_file.exists():
                    with open(local_file, 'r') as f:
                        content = f.read()
                        print(f"    📄 Content preview: {content[:50]}...")
            else:
                print(f"    ❌ Download/decryption failed")
        
        # Direct encryption/decryption test
        print("\\n🧪 Testing direct encryption/decryption...")
        cipher = RSAOAEPCipher(hsm)
        
        test_message = "Hello, CloudHSM! This is a direct encryption test."
        print(f"  Original message: {test_message}")
        
        # Encrypt
        encrypted_data = cipher.encrypt(test_message, public_key)
        if encrypted_data:
            print(f"  ✅ Encryption successful ({len(encrypted_data)} bytes)")
            
            # Decrypt
            decrypted_data = cipher.decrypt(encrypted_data, private_key)
            if decrypted_data:
                decrypted_message = decrypted_data.decode('utf-8')
                print(f"  ✅ Decryption successful: {decrypted_message}")
                
                if decrypted_message == test_message:
                    print("  ✅ Message integrity verified!")
                else:
                    print("  ❌ Message integrity check failed!")
            else:
                print("  ❌ Decryption failed")
        else:
            print("  ❌ Encryption failed")
        
        print("\\n🎉 Demo completed successfully!")
        print("\\n📚 Next steps:")
        print("  1. Modify configuration in config/cloudhsm_config.json")
        print("  2. Run individual examples in the examples/ directory")
        print("  3. Check the tests/ directory for unit tests")
        print("  4. Review logs for detailed operation information")
        
    except Exception as e:
        logger.error(f"Demo failed: {str(e)}")
        print(f"❌ Demo failed: {str(e)}")
    
    finally:
        # Cleanup
        print("\\n🧹 Cleaning up...")
        hsm.disconnect()
        print("✅ CloudHSM session closed")


if __name__ == "__main__":
    main()
'''

# Write the main example to file
with open('main_example.py', 'w') as f:
    f.write(main_example_code)

print("✅ Created config_manager.py")
print("✅ Created main_example.py")
print("📁 Config manager size:", len(config_manager_code), "characters")
print("📁 Main example size:", len(main_example_code), "characters")
print("🔧 Additional features:")
print("  - Configuration management with defaults")
print("  - Complete workflow demonstration")
print("  - Sample file generation")
print("  - Comprehensive testing and verification")
print("  - Error handling and cleanup")