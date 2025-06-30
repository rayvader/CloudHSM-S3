# Create the S3 encryption manager
s3_encryption_code = '''"""
S3 Encryption Manager Module

This module provides S3 integration with CloudHSM-based encryption/decryption
using RSA-OAEP padding for secure file operations.
"""

import os
import json
import base64
import logging
import boto3
from typing import Optional, Dict, Any, Union
from botocore.exceptions import ClientError, NoCredentialsError
from .cloudhsm_manager import CloudHSMManager
from .crypto_utils import RSAOAEPCipher, HybridCipher
from .config_manager import ConfigManager


class S3EncryptionManager:
    """Manages S3 operations with CloudHSM-based encryption."""
    
    def __init__(
        self, 
        bucket_name: str,
        hsm_manager: CloudHSMManager,
        region_name: Optional[str] = None,
        use_hybrid: bool = True
    ):
        """
        Initialize S3 Encryption Manager.
        
        Args:
            bucket_name: S3 bucket name
            hsm_manager: CloudHSMManager instance
            region_name: AWS region (auto-detected if None)
            use_hybrid: Use hybrid encryption for large files
        """
        self.bucket_name = bucket_name
        self.hsm_manager = hsm_manager
        self.use_hybrid = use_hybrid
        self.region_name = region_name
        
        # Initialize S3 client
        try:
            if region_name:
                self.s3_client = boto3.client('s3', region_name=region_name)
            else:
                self.s3_client = boto3.client('s3')
                
            # Get bucket region if not specified
            if not self.region_name:
                try:
                    response = self.s3_client.get_bucket_location(Bucket=bucket_name)
                    self.region_name = response.get('LocationConstraint', 'us-east-1')
                    if self.region_name is None:
                        self.region_name = 'us-east-1'
                except ClientError:
                    self.region_name = 'us-east-1'
                    
        except (NoCredentialsError, ClientError) as e:
            raise Exception(f"Failed to initialize S3 client: {str(e)}")
        
        # Initialize encryption utilities
        self.rsa_cipher = RSAOAEPCipher(hsm_manager)
        self.hybrid_cipher = HybridCipher(hsm_manager) if use_hybrid else None
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # File size threshold for hybrid encryption (1MB)
        self.hybrid_threshold = 1024 * 1024
    
    def _ensure_bucket_exists(self) -> bool:
        """
        Ensure S3 bucket exists, create if it doesn't.
        
        Returns:
            bool: True if bucket exists or was created successfully
        """
        try:
            # Check if bucket exists
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            self.logger.info(f"Bucket {self.bucket_name} exists")
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code == '404':
                # Bucket doesn't exist, create it
                try:
                    if self.region_name == 'us-east-1':
                        self.s3_client.create_bucket(Bucket=self.bucket_name)
                    else:
                        self.s3_client.create_bucket(
                            Bucket=self.bucket_name,
                            CreateBucketConfiguration={'LocationConstraint': self.region_name}
                        )
                    
                    self.logger.info(f"Created bucket {self.bucket_name}")
                    return True
                    
                except ClientError as create_error:
                    self.logger.error(f"Failed to create bucket: {str(create_error)}")
                    return False
            else:
                self.logger.error(f"Error checking bucket: {str(e)}")
                return False
    
    def encrypt_and_upload(
        self, 
        local_file_path: str, 
        s3_key: str,
        public_key_label: str,
        metadata: Optional[Dict[str, str]] = None
    ) -> bool:
        """
        Encrypt local file and upload to S3.
        
        Args:
            local_file_path: Path to local file
            s3_key: S3 object key
            public_key_label: Label of public key in CloudHSM
            metadata: Optional metadata to store with object
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not os.path.exists(local_file_path):
            self.logger.error(f"Local file not found: {local_file_path}")
            return False
        
        if not self._ensure_bucket_exists():
            return False
        
        try:
            # Get public key from CloudHSM
            public_key = self.hsm_manager.find_key_by_label(
                f"{public_key_label}-public", "public"
            )
            if not public_key:
                self.logger.error(f"Public key not found: {public_key_label}-public")
                return False
            
            # Read file
            with open(local_file_path, 'rb') as f:
                file_data = f.read()
            
            file_size = len(file_data)
            self.logger.info(f"Encrypting file: {local_file_path} ({file_size} bytes)")
            
            # Choose encryption method based on file size
            if self.use_hybrid and file_size > self.hybrid_threshold:
                self.logger.info("Using hybrid encryption for large file")
                encrypted_result = self.hybrid_cipher.encrypt(file_data, public_key)
                encryption_method = "hybrid"
            else:
                self.logger.info("Using RSA-OAEP encryption")
                if file_size > 190:  # Approximate RSA-OAEP limit for 2048-bit key
                    encrypted_result = self.rsa_cipher.encrypt_large_data(file_data, public_key)
                    encryption_method = "rsa_chunked"
                else:
                    encrypted_data = self.rsa_cipher.encrypt(file_data, public_key)
                    if encrypted_data:
                        encrypted_result = {"data": encrypted_data}
                        encryption_method = "rsa_direct"
                    else:
                        encrypted_result = None
            
            if not encrypted_result:
                self.logger.error("Encryption failed")
                return False
            
            # Prepare upload data
            upload_data = {
                "encryption_method": encryption_method,
                "encrypted_data": encrypted_result,
                "original_filename": os.path.basename(local_file_path),
                "original_size": file_size,
                "key_label": public_key_label
            }
            
            # Convert to JSON and encode
            upload_json = json.dumps(upload_data, default=self._json_serializer)
            upload_bytes = upload_json.encode('utf-8')
            
            # Prepare metadata
            object_metadata = {
                "encryption-method": encryption_method,
                "key-label": public_key_label,
                "original-size": str(file_size),
                "original-filename": os.path.basename(local_file_path)
            }
            
            if metadata:
                object_metadata.update(metadata)
            
            # Upload to S3
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=s3_key,
                Body=upload_bytes,
                ContentType='application/json',
                Metadata=object_metadata
            )
            
            self.logger.info(f"Successfully uploaded encrypted file to s3://{self.bucket_name}/{s3_key}")
            return True
            
        except Exception as e:
            self.logger.error(f"Encrypt and upload failed: {str(e)}")
            return False
    
    def download_and_decrypt(
        self, 
        s3_key: str, 
        local_file_path: str,
        private_key_label: str
    ) -> bool:
        """
        Download encrypted file from S3 and decrypt.
        
        Args:
            s3_key: S3 object key
            local_file_path: Path to save decrypted file
            private_key_label: Label of private key in CloudHSM
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get private key from CloudHSM
            private_key = self.hsm_manager.find_key_by_label(
                f"{private_key_label}-private", "private"
            )
            if not private_key:
                self.logger.error(f"Private key not found: {private_key_label}-private")
                return False
            
            # Download from S3
            self.logger.info(f"Downloading from s3://{self.bucket_name}/{s3_key}")
            response = self.s3_client.get_object(Bucket=self.bucket_name, Key=s3_key)
            
            # Parse downloaded data
            download_data = json.loads(response['Body'].read().decode('utf-8'))
            
            encryption_method = download_data["encryption_method"]
            encrypted_data = download_data["encrypted_data"]
            
            self.logger.info(f"Decrypting using method: {encryption_method}")
            
            # Decrypt based on encryption method
            if encryption_method == "hybrid":
                decrypted_data = self.hybrid_cipher.decrypt(encrypted_data, private_key)
            elif encryption_method == "rsa_chunked":
                decrypted_data = self.rsa_cipher.decrypt_large_data(encrypted_data, private_key)
            elif encryption_method == "rsa_direct":
                decrypted_data = self.rsa_cipher.decrypt(encrypted_data["data"], private_key)
            else:
                self.logger.error(f"Unknown encryption method: {encryption_method}")
                return False
            
            if decrypted_data is None:
                self.logger.error("Decryption failed")
                return False
            
            # Write decrypted file
            os.makedirs(os.path.dirname(local_file_path), exist_ok=True)
            with open(local_file_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.logger.info(f"Successfully decrypted and saved: {local_file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Download and decrypt failed: {str(e)}")
            return False
    
    def list_encrypted_files(self, prefix: str = "") -> Dict[str, Any]:
        """
        List encrypted files in S3 bucket.
        
        Args:
            prefix: S3 key prefix to filter files
            
        Returns:
            Dictionary with file information
        """
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix
            )
            
            files = []
            if 'Contents' in response:
                for obj in response['Contents']:
                    # Get metadata
                    metadata_response = self.s3_client.head_object(
                        Bucket=self.bucket_name,
                        Key=obj['Key']
                    )
                    
                    file_info = {
                        "key": obj['Key'],
                        "size": obj['Size'],
                        "last_modified": obj['LastModified'].isoformat(),
                        "encryption_method": metadata_response.get('Metadata', {}).get('encryption-method'),
                        "key_label": metadata_response.get('Metadata', {}).get('key-label'),
                        "original_size": metadata_response.get('Metadata', {}).get('original-size'),
                        "original_filename": metadata_response.get('Metadata', {}).get('original-filename')
                    }
                    files.append(file_info)
            
            result = {
                "bucket": self.bucket_name,
                "prefix": prefix,
                "file_count": len(files),
                "files": files
            }
            
            self.logger.info(f"Listed {len(files)} encrypted files")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to list files: {str(e)}")
            return {"bucket": self.bucket_name, "prefix": prefix, "file_count": 0, "files": []}
    
    def delete_encrypted_file(self, s3_key: str) -> bool:
        """
        Delete encrypted file from S3.
        
        Args:
            s3_key: S3 object key to delete
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=s3_key)
            self.logger.info(f"Deleted s3://{self.bucket_name}/{s3_key}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete file: {str(e)}")
            return False
    
    def _json_serializer(self, obj):
        """JSON serializer for bytes objects."""
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode('ascii')
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    
    def get_file_metadata(self, s3_key: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for encrypted file.
        
        Args:
            s3_key: S3 object key
            
        Returns:
            Dictionary with file metadata or None if not found
        """
        try:
            response = self.s3_client.head_object(Bucket=self.bucket_name, Key=s3_key)
            
            metadata = {
                "key": s3_key,
                "size": response['ContentLength'],
                "last_modified": response['LastModified'].isoformat(),
                "etag": response['ETag'],
                "content_type": response['ContentType'],
                "metadata": response.get('Metadata', {})
            }
            
            return metadata
            
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                self.logger.warning(f"File not found: {s3_key}")
            else:
                self.logger.error(f"Error getting metadata: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"Error getting metadata: {str(e)}")
            return None
'''

# Write the S3 encryption manager to file
with open('s3_encryption.py', 'w') as f:
    f.write(s3_encryption_code)

print("✅ Created s3_encryption.py")
print("📁 Size:", len(s3_encryption_code), "characters")
print("🔧 Features included:")
print("  - S3 upload/download with encryption")
print("  - Automatic bucket management")
print("  - Multiple encryption methods support")
print("  - File metadata handling")
print("  - Large file support with hybrid encryption")
print("  - Comprehensive error handling and logging")