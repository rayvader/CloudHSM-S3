# CloudHSM PKCS#11 Python Project

Python sample code that encrypts and decrypts text files stored in Amazon S3 with RSA keys held in AWS CloudHSM, using the PKCS#11 interface and RSA-OAEP padding.

## Features

- `CloudHSMManager`: loads the CloudHSM PKCS#11 library, opens a session as a crypto user, generates RSA key pairs (non-extractable private key by default), and finds, lists and deletes keys by label.
- `RSAOAEPCipher`: RSA-OAEP encrypt/decrypt inside the HSM, with a configurable OAEP hash (SHA1, SHA224, SHA256, SHA384, SHA512) and chunking for larger payloads.
- `HybridCipher`: RSA-OAEP + AES hybrid encryption for large data.
- `S3EncryptionManager`: encrypts a local file and uploads it to S3, downloads and decrypts it, lists encrypted objects and reads their metadata. Files over 1 MiB use hybrid encryption when `use_hybrid=True` (the default). It creates the bucket if it does not exist.
- `ConfigManager`: reads settings from a JSON file and writes a default one if the file is missing.
- `main_example.py`: end-to-end demo (create sample files, generate a key pair, upload, list, download, decrypt, verify).

## Tech stack

- Python 3.8+
- [python-pkcs11](https://pypi.org/project/python-pkcs11/) against the CloudHSM Client SDK 5 PKCS#11 library
- boto3 for Amazon S3
- plotly + kaleido (only for `chart_script.py`)

## Project structure

```
.
├── README.md
├── requirements.txt       # Python dependencies
├── cloudhsm_manager.py    # CloudHSM PKCS#11 connection and key management
├── crypto_utils.py        # RSAOAEPCipher and HybridCipher
├── s3_encryption.py       # S3EncryptionManager (encrypt+upload, download+decrypt)
├── config_manager.py      # JSON configuration loader
├── main_example.py        # End-to-end demo
├── chart_script.py        # Renders cloudhsm_flow.png (workflow diagram) with plotly
├── cloudhsm_flow.png      # Workflow diagram
├── script.py              # Prints the intended package layout
└── script_1.py … script_4.py  # Generators that write the module files above
```

The modules use package-relative imports (for example `from .config_manager import ConfigManager`), so they are meant to live together in a Python package, such as a `src/` directory with an `__init__.py`. `main_example.py` adds `../src` to `sys.path` and imports the modules by plain name, so it does not run as-is from the repository root. Place the modules in a package before using them.

## Prerequisites

### AWS account

- AWS account with permissions for CloudHSM, S3 and EC2
- VPC with subnets for the CloudHSM cluster
- EC2 instance in that VPC to run the CloudHSM client and this code

### System

- Python 3.8 or higher
- AWS CLI, configured with credentials
- Linux or Windows EC2 instance (Amazon Linux 2, Ubuntu or Windows Server)
- CloudHSM Client SDK 5 with the PKCS#11 library

## AWS and CloudHSM setup

### Step 1: AWS Infrastructure Setup

#### 1.1 Create IAM User
```bash
# Create IAM user with necessary permissions
aws iam create-user --user-name cloudhsm-demo-user
aws iam attach-user-policy --user-name cloudhsm-demo-user --policy-arn arn:aws:iam::aws:policy/CloudHSMFullAccess
aws iam attach-user-policy --user-name cloudhsm-demo-user --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
aws iam attach-user-policy --user-name cloudhsm-demo-user --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
```

These managed policies are broad. Scope them down for anything beyond a test account.

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
aws cloudhsmv2 create-cluster \
  --hsm-type hsm2m.medium \
  --subnet-ids <subnet-id-1> <subnet-id-2> \
  --backup-retention-policy Type=DAYS,Value=90
```

#### 2.2 Create HSM Instance
```bash
aws cloudhsmv2 create-hsm \
  --cluster-id <cluster-id> \
  --availability-zone <az-1>
```

#### 2.3 Initialize Cluster
```bash
# Get cluster CSR
aws cloudhsmv2 describe-clusters \
  --filters clusterIds=<cluster-id> \
  --output text \
  --query 'Clusters[].Certificates.ClusterCsr' > cluster_csr.csr

# Create a signing certificate and sign the CSR
openssl genrsa -aes256 -out customerCA.key 2048
openssl req -new -x509 -days 3652 -key customerCA.key -out customerCA.crt
openssl x509 -req -days 3652 -in cluster_csr.csr \
  -CA customerCA.crt -CAkey customerCA.key \
  -CAcreateserial -out cluster_certificate.crt

# Initialize cluster
aws cloudhsmv2 initialize-cluster \
  --cluster-id <cluster-id> \
  --signed-cert file://cluster_certificate.crt \
  --trust-anchor file://customerCA.crt
```

Keep `customerCA.key` out of this repository.

### Step 3: EC2 Client Setup

#### 3.1 Launch EC2 Instance
```bash
aws ec2 run-instances \
  --image-id <ami-id> \
  --instance-type t3.medium \
  --key-name <key-pair-name> \
  --subnet-id <subnet-id> \
  --security-group-ids <security-group-id>
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

## Install

```bash
git clone https://github.com/rayvader/CloudHSM-S3.git
cd CloudHSM-S3

python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

pip install -r requirements.txt
```

`requirements.txt` also pins test, lint and docs tools (pytest, moto, black, flake8, mypy, sphinx). They are not needed to run the code.

## Configuration

Settings come from a JSON file, `config/cloudhsm_config.json` by default, resolved from the current working directory. Pass another path to `ConfigManager(config_path)` or `CloudHSMManager(config_path)`. If the file is missing, `ConfigManager` writes one with placeholder values. Edit it before connecting.

| Section | Key | Meaning |
|---|---|---|
| `cloudhsm` | `cluster_id` | CloudHSM cluster ID |
| `cloudhsm` | `pkcs11_library_path` | Path to the PKCS#11 library, default `/opt/cloudhsm/lib/libcloudhsm_pkcs11_standard.so` |
| `cloudhsm` | `crypto_user` | Crypto user name |
| `cloudhsm` | `crypto_password` | Crypto user password, used as the PKCS#11 PIN |
| `aws` | `region` | AWS region |
| `aws` | `s3_bucket` | Bucket used by `main_example.py` |
| `encryption` | `key_label` | Base label for the RSA key pair (`<label>-public`, `<label>-private`) |
| `encryption` | `key_size` | RSA key size in bits, default 2048 |
| `encryption` | `hash_algorithm` | OAEP hash, default `SHA256` |
| `encryption` | `mgf` | Mask generation function, default `MGF1` |
| `logging` | `level`, `format` | Python logging settings |

The config file holds the crypto user password in plain text. Do not commit it, and restrict its file permissions. No environment variables are read; AWS credentials come from the standard boto3 credential chain.

## Usage

With the modules in a `src/` package:

```python
from src.cloudhsm_manager import CloudHSMManager
from src.crypto_utils import RSAOAEPCipher
from src.s3_encryption import S3EncryptionManager

hsm = CloudHSMManager()          # reads config/cloudhsm_config.json
hsm.connect()

public_key, private_key = hsm.generate_rsa_keypair(key_size=2048, label="rsa-oaep-key")

# Direct RSA-OAEP
cipher = RSAOAEPCipher(hsm)
ciphertext = cipher.encrypt(b"Hello, CloudHSM!", public_key)
print(cipher.decrypt(ciphertext, private_key).decode())

# S3
s3 = S3EncryptionManager(bucket_name="<your-bucket>", hsm_manager=hsm)
s3.encrypt_and_upload("local_file.txt", "encrypted/file.txt", public_key_label="rsa-oaep-key")
s3.download_and_decrypt("encrypted/file.txt", "decrypted_file.txt", private_key_label="rsa-oaep-key")

hsm.disconnect()
```

`CloudHSMManager` is also a context manager (`with CloudHSMManager() as hsm:`).

### Demo

`main_example.py` runs the full flow: it writes sample files to `tests/sample_data/`, generates a key pair, uploads the files encrypted to `s3://<s3_bucket>/encrypted/`, lists them, downloads and decrypts them to `tests/decrypted/`, and checks a direct encrypt/decrypt round trip. See the import note under [Project structure](#project-structure) before running it.

### Workflow diagram

```bash
python chart_script.py   # writes cloudhsm_flow.png; installs kaleido if missing
```

## Testing

There are no automated tests in this repository yet. `main_example.py` is the end-to-end check and needs a live CloudHSM cluster and S3 bucket.

## Deploy

Nothing is deployed. The code runs on an EC2 instance that can reach the CloudHSM cluster.

## Troubleshooting

1. **PKCS#11 library not found**
   ```bash
   ls -la /opt/cloudhsm/lib/libcloudhsm_pkcs11_standard.so
   cat /opt/cloudhsm/etc/cloudhsm_pkcs11.cfg
   ```

2. **Connection timeout**
   ```bash
   aws cloudhsmv2 describe-clusters --filters clusterIds=<cluster-id>
   aws ec2 describe-security-groups --group-ids <security-group-id>
   ```

3. **Authentication failed**
   ```bash
   /opt/cloudhsm/bin/cloudhsm-cli interactive
   aws-cloudhsm > user list
   ```

## Security considerations

1. **Key management**: keep private keys non-extractable in CloudHSM.
2. **Access control**: use least-privilege IAM policies and separate HSM users.
3. **Secrets**: keep the crypto user password and `customerCA.key` out of source control.
4. **Network security**: use VPC endpoints and tight security groups.
5. **Audit logging**: enable CloudTrail and CloudHSM audit logs.
6. **Backups**: set a backup retention policy on the cluster.

## Additional resources

- [AWS CloudHSM User Guide](https://docs.aws.amazon.com/cloudhsm/latest/userguide/)
- [PKCS#11 Cryptographic Token Interface Standard](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
- [AWS CloudHSM PKCS#11 Examples](https://github.com/aws-samples/aws-cloudhsm-pkcs11-examples)

## License

No license file is included in this repository.
