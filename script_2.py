# Create the cryptographic utilities module
crypto_utils_code = '''"""
Cryptographic Utilities Module

This module provides RSA-OAEP encryption/decryption utilities
for use with AWS CloudHSM and PKCS#11.
"""

import logging
import pkcs11
from typing import Optional, Union, Dict, Any
from pkcs11 import Mechanism, MGF
from pkcs11.exceptions import PKCS11Error


class RSAOAEPCipher:
    """RSA-OAEP encryption/decryption using CloudHSM."""
    
    def __init__(self, hsm_manager, hash_algorithm: str = "SHA256", mgf: str = "MGF1"):
        """
        Initialize RSA-OAEP cipher.
        
        Args:
            hsm_manager: CloudHSMManager instance
            hash_algorithm: Hash algorithm for OAEP (SHA1, SHA224, SHA256, SHA384, SHA512)
            mgf: Mask Generation Function (MGF1)
        """
        self.hsm = hsm_manager
        self.hash_algorithm = hash_algorithm
        self.mgf = mgf
        self.logger = logging.getLogger(__name__)
        
        # Map hash algorithms to PKCS#11 mechanisms
        self.hash_mechanisms = {
            "SHA1": Mechanism.SHA_1,
            "SHA224": Mechanism.SHA224,
            "SHA256": Mechanism.SHA256,
            "SHA384": Mechanism.SHA384,
            "SHA512": Mechanism.SHA512,
        }
        
        # Map MGF algorithms
        self.mgf_algorithms = {
            "MGF1": MGF.SHA1,  # Default MGF1 with SHA1
            "MGF1_SHA1": MGF.SHA1,
            "MGF1_SHA224": MGF.SHA224,
            "MGF1_SHA256": MGF.SHA256,
            "MGF1_SHA384": MGF.SHA384,
            "MGF1_SHA512": MGF.SHA512,
        }
    
    def _get_oaep_mechanism(self, label: Optional[bytes] = None) -> Mechanism:
        """
        Get RSA-OAEP mechanism with specified parameters.
        
        Args:
            label: Optional label for OAEP padding
            
        Returns:
            PKCS#11 Mechanism for RSA-OAEP
        """
        try:
            hash_mech = self.hash_mechanisms.get(self.hash_algorithm, Mechanism.SHA256)
            mgf_func = self.mgf_algorithms.get(self.mgf, MGF.SHA256)
            
            # Create OAEP mechanism parameters
            mechanism_param = (hash_mech, mgf_func, label)
            
            return Mechanism.RSA_PKCS_OAEP, mechanism_param
            
        except Exception as e:
            self.logger.error(f"Error creating OAEP mechanism: {str(e)}")
            raise
    
    def encrypt(
        self, 
        plaintext: Union[str, bytes], 
        public_key, 
        label: Optional[bytes] = None
    ) -> Optional[bytes]:
        """
        Encrypt data using RSA-OAEP.
        
        Args:
            plaintext: Data to encrypt (string or bytes)
            public_key: RSA public key from CloudHSM
            label: Optional label for OAEP padding
            
        Returns:
            Encrypted data as bytes, or None if failed
        """
        if not self.hsm.session:
            self.logger.error("No active HSM session")
            return None
        
        try:
            # Convert string to bytes if necessary
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            # Get OAEP mechanism
            mechanism, mechanism_param = self._get_oaep_mechanism(label)
            
            # Perform encryption
            self.logger.info(f"Encrypting {len(plaintext)} bytes using RSA-OAEP")
            ciphertext = public_key.encrypt(
                plaintext, 
                mechanism=mechanism,
                mechanism_param=mechanism_param
            )
            
            self.logger.info(f"Encryption successful, ciphertext size: {len(ciphertext)} bytes")
            return ciphertext
            
        except Exception as e:
            self.logger.error(f"Encryption failed: {str(e)}")
            return None
    
    def decrypt(
        self, 
        ciphertext: bytes, 
        private_key, 
        label: Optional[bytes] = None
    ) -> Optional[bytes]:
        """
        Decrypt data using RSA-OAEP.
        
        Args:
            ciphertext: Encrypted data to decrypt
            private_key: RSA private key from CloudHSM
            label: Optional label for OAEP padding (must match encryption)
            
        Returns:
            Decrypted data as bytes, or None if failed
        """
        if not self.hsm.session:
            self.logger.error("No active HSM session")
            return None
        
        try:
            # Get OAEP mechanism
            mechanism, mechanism_param = self._get_oaep_mechanism(label)
            
            # Perform decryption
            self.logger.info(f"Decrypting {len(ciphertext)} bytes using RSA-OAEP")
            plaintext = private_key.decrypt(
                ciphertext, 
                mechanism=mechanism,
                mechanism_param=mechanism_param
            )
            
            self.logger.info(f"Decryption successful, plaintext size: {len(plaintext)} bytes")
            return plaintext
            
        except Exception as e:
            self.logger.error(f"Decryption failed: {str(e)}")
            return None
    
    def encrypt_large_data(
        self, 
        data: Union[str, bytes], 
        public_key, 
        chunk_size: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Encrypt large data by splitting into chunks.
        
        Note: For large data, consider using hybrid encryption (RSA + AES)
        
        Args:
            data: Large data to encrypt
            public_key: RSA public key
            chunk_size: Size of each chunk (auto-calculated if None)
            
        Returns:
            Dictionary with encrypted chunks and metadata
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            # Calculate max chunk size based on key size
            if chunk_size is None:
                # For RSA-OAEP, max plaintext size is roughly (key_size/8) - 2*hash_size - 2
                # For 2048-bit key with SHA256: 2048/8 - 2*32 - 2 = 190 bytes
                key_size_bits = public_key[pkcs11.Attribute.MODULUS_BITS]
                hash_size = 32 if self.hash_algorithm == "SHA256" else 20  # Simplified
                chunk_size = (key_size_bits // 8) - (2 * hash_size) - 2
                chunk_size = max(chunk_size - 50, 100)  # Safety margin
            
            self.logger.info(f"Encrypting {len(data)} bytes in chunks of {chunk_size}")
            
            # Split data into chunks
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            encrypted_chunks = []
            
            # Encrypt each chunk
            for i, chunk in enumerate(chunks):
                encrypted_chunk = self.encrypt(chunk, public_key)
                if encrypted_chunk is None:
                    self.logger.error(f"Failed to encrypt chunk {i}")
                    return None
                encrypted_chunks.append(encrypted_chunk)
            
            result = {
                "chunks": encrypted_chunks,
                "chunk_count": len(chunks),
                "original_size": len(data),
                "chunk_size": chunk_size,
                "hash_algorithm": self.hash_algorithm,
                "mgf": self.mgf
            }
            
            self.logger.info(f"Successfully encrypted {len(chunks)} chunks")
            return result
            
        except Exception as e:
            self.logger.error(f"Large data encryption failed: {str(e)}")
            return None
    
    def decrypt_large_data(
        self, 
        encrypted_data: Dict[str, Any], 
        private_key
    ) -> Optional[bytes]:
        """
        Decrypt large data from chunks.
        
        Args:
            encrypted_data: Dictionary from encrypt_large_data()
            private_key: RSA private key
            
        Returns:
            Decrypted data as bytes
        """
        try:
            chunks = encrypted_data["chunks"]
            self.logger.info(f"Decrypting {len(chunks)} chunks")
            
            decrypted_chunks = []
            
            # Decrypt each chunk
            for i, encrypted_chunk in enumerate(chunks):
                decrypted_chunk = self.decrypt(encrypted_chunk, private_key)
                if decrypted_chunk is None:
                    self.logger.error(f"Failed to decrypt chunk {i}")
                    return None
                decrypted_chunks.append(decrypted_chunk)
            
            # Combine chunks
            result = b"".join(decrypted_chunks)
            
            # Verify size
            expected_size = encrypted_data.get("original_size", len(result))
            if len(result) != expected_size:
                self.logger.warning(f"Size mismatch: expected {expected_size}, got {len(result)}")
            
            self.logger.info(f"Successfully decrypted {len(result)} bytes")
            return result
            
        except Exception as e:
            self.logger.error(f"Large data decryption failed: {str(e)}")
            return None


class HybridCipher:
    """Hybrid encryption using RSA-OAEP + AES for large data."""
    
    def __init__(self, hsm_manager):
        """
        Initialize hybrid cipher.
        
        Args:
            hsm_manager: CloudHSMManager instance
        """
        self.hsm = hsm_manager
        self.rsa_cipher = RSAOAEPCipher(hsm_manager)
        self.logger = logging.getLogger(__name__)
    
    def encrypt(
        self, 
        data: Union[str, bytes], 
        public_key
    ) -> Optional[Dict[str, Any]]:
        """
        Encrypt data using hybrid encryption (RSA-OAEP + AES).
        
        Args:
            data: Data to encrypt
            public_key: RSA public key for key encryption
            
        Returns:
            Dictionary with encrypted data and encrypted AES key
        """
        if not self.hsm.session:
            self.logger.error("No active HSM session")
            return None
        
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Generate AES key
            aes_key = self.hsm.session.generate_key(
                pkcs11.KeyType.AES,
                256,  # 256-bit AES key
                template={
                    pkcs11.Attribute.ENCRYPT: True,
                    pkcs11.Attribute.DECRYPT: True,
                    pkcs11.Attribute.EXTRACTABLE: True,  # Needed for RSA encryption
                    pkcs11.Attribute.TOKEN: False,  # Session key
                }
            )
            
            # Encrypt data with AES
            iv = self.hsm.session.generate_random(16)  # 128-bit IV for AES
            encrypted_data = aes_key.encrypt(data, mechanism_param=iv)
            
            # Extract AES key value for RSA encryption
            aes_key_bytes = aes_key[pkcs11.Attribute.VALUE]
            
            # Encrypt AES key with RSA-OAEP
            encrypted_aes_key = self.rsa_cipher.encrypt(aes_key_bytes, public_key)
            
            if encrypted_aes_key is None:
                self.logger.error("Failed to encrypt AES key")
                return None
            
            # Clean up session AES key
            aes_key.destroy()
            
            result = {
                "encrypted_data": encrypted_data,
                "encrypted_key": encrypted_aes_key,
                "iv": iv,
                "algorithm": "AES-256-CBC",
                "key_algorithm": "RSA-OAEP"
            }
            
            self.logger.info(f"Hybrid encryption successful: {len(data)} bytes")
            return result
            
        except Exception as e:
            self.logger.error(f"Hybrid encryption failed: {str(e)}")
            return None
    
    def decrypt(
        self, 
        encrypted_data: Dict[str, Any], 
        private_key
    ) -> Optional[bytes]:
        """
        Decrypt data using hybrid decryption.
        
        Args:
            encrypted_data: Result from hybrid encrypt()
            private_key: RSA private key for key decryption
            
        Returns:
            Decrypted data as bytes
        """
        if not self.hsm.session:
            self.logger.error("No active HSM session")
            return None
        
        try:
            # Decrypt AES key with RSA-OAEP
            aes_key_bytes = self.rsa_cipher.decrypt(
                encrypted_data["encrypted_key"], 
                private_key
            )
            
            if aes_key_bytes is None:
                self.logger.error("Failed to decrypt AES key")
                return None
            
            # Import AES key into HSM
            aes_key = self.hsm.session.create_object({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.AES,
                pkcs11.Attribute.VALUE: aes_key_bytes,
                pkcs11.Attribute.ENCRYPT: True,
                pkcs11.Attribute.DECRYPT: True,
                pkcs11.Attribute.TOKEN: False,  # Session key
            })
            
            # Decrypt data with AES
            plaintext = aes_key.decrypt(
                encrypted_data["encrypted_data"],
                mechanism_param=encrypted_data["iv"]
            )
            
            # Clean up session AES key
            aes_key.destroy()
            
            self.logger.info(f"Hybrid decryption successful: {len(plaintext)} bytes")
            return plaintext
            
        except Exception as e:
            self.logger.error(f"Hybrid decryption failed: {str(e)}")
            return None
'''

# Write the crypto utilities to file
with open('crypto_utils.py', 'w') as f:
    f.write(crypto_utils_code)

print("✅ Created crypto_utils.py")
print("📁 Size:", len(crypto_utils_code), "characters")
print("🔧 Features included:")
print("  - RSA-OAEP encryption/decryption")
print("  - Large data handling with chunking") 
print("  - Hybrid encryption (RSA + AES)")
print("  - Configurable hash algorithms and MGF")
print("  - Comprehensive error handling")