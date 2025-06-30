# CloudHSM PKCS#11 Python Project

A comprehensive project demonstrating how to use AWS CloudHSM with Python for encrypting and decrypting S3 bucket text files using PKCS#11 library with PKCS-OAEP padding.

## 🎯 Project Overview

This project provides a complete implementation for:
- Setting up AWS CloudHSM cluster
- Configuring PKCS#11 library integration
- Implementing RSA-OAEP encryption/decryption
- Integrating with Amazon S3 for secure file operations
- Managing cryptographic keys using CloudHSM

## 📋 Prerequisites

### AWS Account Requirements
- AWS account with appropriate permissions
- IAM user with CloudHSM and S3 access
- VPC with public and private subnets
- EC2 instance for CloudHSM client

### System Requirements
- Python 3.8 or higher
- AWS CLI configured
- Linux/Windows EC2 instance (Amazon Linux 2, Ubuntu, or Windows Server)
- CloudHSM Client SDK 5

## 🛠️ Complete Setup Guide

### Step 1: AWS Infrastructure Setup

#### 1.1 Create IAM User
```bash
# Create IAM user with necessary permissions
aws iam create-user --user-name cloudhsm-demo-user
aws iam attach-user-policy --user-name cloudhsm-demo-user --policy-arn arn:aws:iam::aws:policy/CloudHSMFullAccess
aws iam attach-user-policy --user-name cloudhsm-demo-user --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
aws iam attach-user-policy --user-name cloudhsm-demo-user --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
```

#### 1.2 Create VPC and Subnets
```bash
# Create VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=CloudHSM-VPC}]'

# Create public subnet
aws ec2 create-subnet --vpc-id <vpc-id> --cidr-block 10.0.1.0/24 --availability-zone <az-1>

# Create private subnet
aws ec2 create-subnet --vpc-id <vpc-id> --cidr-block 10.0.2.0/24 --availability-zone <az-2>
```

### Step 2: CloudHSM Cluster Setup

#### 2.1 Create CloudHSM Cluster
```bash
# Create cluster
aws cloudhsmv2 create-cluster \
  --hsm-type hsm2m.medium \
  --subnet-ids subnet-12345678 subnet-87654321 \
  --backup-retention-policy Type=DAYS,Value=90
```

#### 2.2 Create HSM Instance
```bash
# Create HSM in the cluster
aws cloudhsmv2 create-hsm \
  --cluster-id cluster-12345678 \
  --availability-zone us-west-2a
```

#### 2.3 Initialize Cluster
```bash
# Get cluster CSR
aws cloudhsmv2 describe-clusters \
  --filters clusterIds=cluster-12345678 \
  --output text \
  --query 'Clusters[].Certificates.ClusterCsr' > cluster_csr.csr

# Create signing certificate (as described in setup guide)
openssl genrsa -aes256 -out customerCA.key 2048
openssl req -new -x509 -days 3652 -key customerCA.key -out customerCA.crt
openssl x509 -req -days 3652 -in cluster_csr.csr \
  -CA customerCA.crt -CAkey customerCA.key \
  -CAcreateserial -out cluster_certificate.crt

# Initialize cluster
aws cloudhsmv2 initialize-cluster \
  --cluster-id cluster-12345678 \
  --signed-cert file://cluster_certificate.crt \
  --trust-anchor file://customerCA.crt
```

### Step 3: EC2 Client Setup

#### 3.1 Launch EC2 Instance
```bash
# Launch EC2 instance
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --instance-type t3.medium \
  --key-name my-key-pair \
  --subnet-id subnet-12345678 \
  --security-group-ids sg-12345678
```

#### 3.2 Install CloudHSM Client
```bash
# On Amazon Linux 2
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-cli-latest.el7.x86_64.rpm
sudo yum install -y ./cloudhsm-cli-latest.el7.x86_64.rpm

# Install PKCS#11 library
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-pkcs11-latest.el7.x86_64.rpm
sudo yum install -y ./cloudhsm-pkcs11-latest.el7.x86_64.rpm
```

#### 3.3 Configure Client
```bash
# Copy issuing certificate
sudo cp customerCA.crt /opt/cloudhsm/etc/customerCA.crt

# Configure CLI
sudo /opt/cloudhsm/bin/configure-cli -a <HSM-IP-ADDRESS>

# Configure PKCS#11
sudo /opt/cloudhsm/bin/configure-pkcs11 -a <HSM-IP-ADDRESS>
```

### Step 4: Activate Cluster
```bash
# Start CloudHSM CLI
/opt/cloudhsm/bin/cloudhsm-cli interactive

# In CloudHSM CLI
aws-cloudhsm > cluster activate
Enter password: <admin-password>
Confirm password: <admin-password>

# Create crypto user
aws-cloudhsm > user create --username crypto-user --role crypto-user
Enter password: <crypto-user-password>
Confirm password: <crypto-user-password>
```

### Step 5: Python Environment Setup

#### 5.1 Install Dependencies
```bash
# Clone this repository
git clone <repository-url>
cd cloudhsm-pkcs11-project

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate

# Install dependencies
pip install -r requirements.txt
```

#### 5.2 Configure Environment
```bash
# Copy configuration template
cp config/cloudhsm_config.json.template config/cloudhsm_config.json

# Edit configuration file
nano config/cloudhsm_config.json
```

## 🔧 Configuration

### CloudHSM Configuration (config/cloudhsm_config.json)
```json
{
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
  }
}
```

## 🚀 Usage Examples

### Basic Encryption/Decryption
```python
from src.cloudhsm_manager import CloudHSMManager
from src.crypto_utils import RSAOAEPCipher

# Initialize CloudHSM manager
hsm = CloudHSMManager()
hsm.connect()

# Create RSA key pair
public_key, private_key = hsm.generate_rsa_keypair(
    key_size=2048,
    label="test-rsa-key"
)

# Encrypt data
cipher = RSAOAEPCipher(hsm)
plaintext = b"Hello, CloudHSM!"
ciphertext = cipher.encrypt(plaintext, public_key)

# Decrypt data
decrypted = cipher.decrypt(ciphertext, private_key)
print(f"Decrypted: {decrypted.decode()}")
```

### S3 Integration
```python
from src.s3_encryption import S3EncryptionManager

# Initialize S3 encryption manager
s3_manager = S3EncryptionManager(
    bucket_name="your-test-bucket",
    hsm_manager=hsm
)

# Encrypt and upload file to S3
s3_manager.encrypt_and_upload("local_file.txt", "encrypted/file.txt")

# Download and decrypt file from S3
s3_manager.download_and_decrypt("encrypted/file.txt", "decrypted_file.txt")
```

## 📁 Project Structure

```
cloudhsm-pkcs11-project/
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── config/                   # Configuration files
│   ├── cloudhsm_config.json # CloudHSM configuration
│   └── aws_config.ini       # AWS configuration template
├── scripts/                  # Setup and utility scripts
│   ├── setup.py             # Project setup script
│   ├── cloudhsm_setup.sh    # CloudHSM cluster setup
│   └── client_setup.sh      # Client configuration
├── src/                      # Main source code
│   ├── __init__.py          # Package initialization
│   ├── cloudhsm_manager.py  # CloudHSM PKCS11 operations
│   ├── s3_encryption.py     # S3 encryption/decryption
│   ├── crypto_utils.py      # Cryptographic utilities
│   └── config_manager.py    # Configuration management
├── examples/                 # Example scripts
│   ├── basic_encryption.py  # Basic encryption example
│   ├── s3_integration.py    # S3 integration example
│   └── key_management.py    # Key management example
├── tests/                    # Test files
│   ├── test_cloudhsm.py     # CloudHSM tests
│   ├── test_s3_encryption.py # S3 encryption tests
│   └── sample_data/         # Test data
└── docs/                     # Documentation
    ├── setup_guide.md       # Detailed setup guide
    ├── troubleshooting.md   # Common issues
    └── api_reference.md     # API documentation
```

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run specific test
pytest tests/test_cloudhsm.py -v

# Run with coverage
pytest --cov=src tests/
```

## 🔍 Troubleshooting

### Common Issues

1. **PKCS#11 Library Not Found**
   ```bash
   # Verify library path
   ls -la /opt/cloudhsm/lib/libcloudhsm_pkcs11_standard.so
   
   # Check configuration
   cat /opt/cloudhsm/etc/cloudhsm_pkcs11.cfg
   ```

2. **Connection Timeout**
   ```bash
   # Check HSM status
   aws cloudhsmv2 describe-clusters --cluster-ids cluster-12345678
   
   # Verify security groups
   aws ec2 describe-security-groups --group-ids sg-12345678
   ```

3. **Authentication Failed**
   ```bash
   # Verify user exists
   /opt/cloudhsm/bin/cloudhsm-cli interactive
   aws-cloudhsm > user list
   ```

## 📚 Additional Resources

- [AWS CloudHSM User Guide](https://docs.aws.amazon.com/cloudhsm/latest/userguide/)
- [PKCS#11 Cryptographic Token Interface Standard](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
- [AWS CloudHSM PKCS#11 Examples](https://github.com/aws-samples/aws-cloudhsm-pkcs11-examples)

## ⚠️ Security Considerations

1. **Key Management**: Store private keys securely in CloudHSM
2. **Access Control**: Implement proper IAM policies and HSM user management
3. **Network Security**: Use VPC endpoints and security groups
4. **Audit Logging**: Enable CloudTrail and CloudHSM audit logs
5. **Backup Strategy**: Implement regular backup procedures

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📧 Support

For issues and questions:
- Create an issue in this repository
- Contact the maintainers
- Check the troubleshooting guide