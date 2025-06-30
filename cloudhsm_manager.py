"""
CloudHSM Manager Module

This module provides a comprehensive interface for interacting with AWS CloudHSM
using the PKCS#11 library for cryptographic operations.
"""

import os
import json
import logging
import pkcs11
from typing import Optional, Tuple, Dict, Any
from pkcs11 import Session, PublicKey, PrivateKey, Mechanism
from pkcs11.exceptions import PKCS11Error
from .config_manager import ConfigManager


class CloudHSMManager:
    """Manages CloudHSM connections and cryptographic operations using PKCS#11."""

    def __init__(self, config_path: str = "config/cloudhsm_config.json"):
        """
        Initialize CloudHSM Manager.

        Args:
            config_path: Path to CloudHSM configuration file
        """
        self.config = ConfigManager(config_path)
        self.lib = None
        self.session = None
        self.token = None
        self._setup_logging()

    def _setup_logging(self):
        """Setup logging for CloudHSM operations."""
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def connect(self) -> bool:
        """
        Establish connection to CloudHSM.

        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            # Load PKCS#11 library
            library_path = self.config.get_cloudhsm_config()['pkcs11_library_path']
            self.logger.info(f"Loading PKCS#11 library from: {library_path}")

            if not os.path.exists(library_path):
                raise FileNotFoundError(f"PKCS#11 library not found: {library_path}")

            self.lib = pkcs11.lib(library_path)

            # Get token
            slots = self.lib.get_slots(token_present=True)
            if not slots:
                raise PKCS11Error("No tokens found")

            self.token = slots[0].get_token()
            self.logger.info(f"Connected to token: {self.token.label}")

            # Open session
            crypto_user = self.config.get_cloudhsm_config()['crypto_user']
            crypto_password = self.config.get_cloudhsm_config()['crypto_password']

            self.session = self.token.open(rw=True, user_pin=crypto_password)
            self.logger.info(f"Session opened for user: {crypto_user}")

            return True

        except Exception as e:
            self.logger.error(f"Failed to connect to CloudHSM: {str(e)}")
            return False

    def disconnect(self):
        """Close CloudHSM session and cleanup resources."""
        try:
            if self.session:
                self.session.close()
                self.session = None
                self.logger.info("CloudHSM session closed")
        except Exception as e:
            self.logger.error(f"Error closing session: {str(e)}")

    def generate_rsa_keypair(
        self, 
        key_size: int = 2048, 
        label: str = "rsa-key",
        extractable: bool = False
    ) -> Tuple[Optional[PublicKey], Optional[PrivateKey]]:
        """
        Generate RSA key pair in CloudHSM.

        Args:
            key_size: RSA key size (1024, 2048, 3072, 4096)
            label: Key label for identification
            extractable: Whether the private key is extractable

        Returns:
            Tuple of (PublicKey, PrivateKey) or (None, None) if failed
        """
        if not self.session:
            self.logger.error("No active session. Call connect() first.")
            return None, None

        try:
            self.logger.info(f"Generating RSA {key_size}-bit key pair with label: {label}")

            # Define key attributes
            public_key_template = {
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY,
                pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
                pkcs11.Attribute.TOKEN: True,
                pkcs11.Attribute.PRIVATE: False,
                pkcs11.Attribute.MODULUS_BITS: key_size,
                pkcs11.Attribute.PUBLIC_EXPONENT: b'\x01\x00\x01',  # 65537
                pkcs11.Attribute.LABEL: f"{label}-public",
                pkcs11.Attribute.ENCRYPT: True,
                pkcs11.Attribute.VERIFY: True,
                pkcs11.Attribute.WRAP: True,
            }

            private_key_template = {
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
                pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
                pkcs11.Attribute.TOKEN: True,
                pkcs11.Attribute.PRIVATE: True,
                pkcs11.Attribute.LABEL: f"{label}-private",
                pkcs11.Attribute.DECRYPT: True,
                pkcs11.Attribute.SIGN: True,
                pkcs11.Attribute.UNWRAP: True,
                pkcs11.Attribute.SENSITIVE: True,
                pkcs11.Attribute.EXTRACTABLE: extractable,
            }

            # Generate key pair
            public_key, private_key = self.session.generate_keypair(
                pkcs11.KeyType.RSA,
                key_size,
                public_template=public_key_template,
                private_template=private_key_template
            )

            self.logger.info(f"Successfully generated RSA key pair: {label}")
            return public_key, private_key

        except Exception as e:
            self.logger.error(f"Failed to generate RSA key pair: {str(e)}")
            return None, None

    def find_key_by_label(self, label: str, key_class: str = "private") -> Optional[Any]:
        """
        Find key by label.

        Args:
            label: Key label to search for
            key_class: "private", "public", or "secret"

        Returns:
            Key object or None if not found
        """
        if not self.session:
            self.logger.error("No active session. Call connect() first.")
            return None

        try:
            if key_class.lower() == "private":
                object_class = pkcs11.ObjectClass.PRIVATE_KEY
            elif key_class.lower() == "public":
                object_class = pkcs11.ObjectClass.PUBLIC_KEY
            elif key_class.lower() == "secret":
                object_class = pkcs11.ObjectClass.SECRET_KEY
            else:
                raise ValueError(f"Invalid key_class: {key_class}")

            keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: object_class,
                pkcs11.Attribute.LABEL: label
            }))

            if keys:
                self.logger.info(f"Found {key_class} key with label: {label}")
                return keys[0]
            else:
                self.logger.warning(f"No {key_class} key found with label: {label}")
                return None

        except Exception as e:
            self.logger.error(f"Error finding key: {str(e)}")
            return None

    def list_keys(self) -> Dict[str, list]:
        """
        List all keys in the HSM.

        Returns:
            Dictionary with lists of public, private, and secret keys
        """
        if not self.session:
            self.logger.error("No active session. Call connect() first.")
            return {"public": [], "private": [], "secret": []}

        try:
            result = {"public": [], "private": [], "secret": []}

            # Find public keys
            public_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY
            }))
            for key in public_keys:
                try:
                    label = key[pkcs11.Attribute.LABEL]
                    result["public"].append(label)
                except:
                    result["public"].append("(unlabeled)")

            # Find private keys
            private_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY
            }))
            for key in private_keys:
                try:
                    label = key[pkcs11.Attribute.LABEL]
                    result["private"].append(label)
                except:
                    result["private"].append("(unlabeled)")

            # Find secret keys
            secret_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY
            }))
            for key in secret_keys:
                try:
                    label = key[pkcs11.Attribute.LABEL]
                    result["secret"].append(label)
                except:
                    result["secret"].append("(unlabeled)")

            self.logger.info(f"Found {len(public_keys)} public, {len(private_keys)} private, {len(secret_keys)} secret keys")
            return result

        except Exception as e:
            self.logger.error(f"Error listing keys: {str(e)}")
            return {"public": [], "private": [], "secret": []}

    def delete_key(self, label: str, key_class: str = "both") -> bool:
        """
        Delete key(s) by label.

        Args:
            label: Key label to delete
            key_class: "private", "public", "secret", or "both" (private+public)

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.session:
            self.logger.error("No active session. Call connect() first.")
            return False

        try:
            deleted = False

            if key_class in ["private", "both"]:
                private_key = self.find_key_by_label(f"{label}-private", "private")
                if private_key:
                    private_key.destroy()
                    self.logger.info(f"Deleted private key: {label}-private")
                    deleted = True

            if key_class in ["public", "both"]:
                public_key = self.find_key_by_label(f"{label}-public", "public")
                if public_key:
                    public_key.destroy()
                    self.logger.info(f"Deleted public key: {label}-public")
                    deleted = True

            if key_class == "secret":
                secret_key = self.find_key_by_label(label, "secret")
                if secret_key:
                    secret_key.destroy()
                    self.logger.info(f"Deleted secret key: {label}")
                    deleted = True

            return deleted

        except Exception as e:
            self.logger.error(f"Error deleting key: {str(e)}")
            return False

    def get_session(self) -> Optional[Session]:
        """Get the current PKCS#11 session."""
        return self.session

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
