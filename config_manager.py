"""
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
