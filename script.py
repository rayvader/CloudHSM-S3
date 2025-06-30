# Create a comprehensive project structure for CloudHSM PKCS11 with Python
import os
import json

# Project structure
project_structure = {
    "cloudhsm-pkcs11-project/": {
        "README.md": "Project documentation",
        "requirements.txt": "Python dependencies",
        "config/": {
            "cloudhsm_config.json": "CloudHSM configuration",
            "aws_config.ini": "AWS configuration template"
        },
        "scripts/": {
            "setup.py": "Project setup script",
            "cloudhsm_setup.sh": "CloudHSM cluster setup script",
            "client_setup.sh": "Client configuration script"
        },
        "src/": {
            "__init__.py": "Package initialization",
            "cloudhsm_manager.py": "CloudHSM PKCS11 operations",
            "s3_encryption.py": "S3 encryption/decryption operations", 
            "crypto_utils.py": "Cryptographic utilities",
            "config_manager.py": "Configuration management"
        },
        "examples/": {
            "basic_encryption.py": "Basic RSA-OAEP encryption example",
            "s3_integration.py": "S3 encryption integration example",
            "key_management.py": "Key generation and management"
        },
        "tests/": {
            "test_cloudhsm.py": "CloudHSM tests",
            "test_s3_encryption.py": "S3 encryption tests",
            "sample_data/": {
                "test_file1.txt": "Sample text file",
                "test_file2.txt": "Another sample file"
            }
        },
        "docs/": {
            "setup_guide.md": "Detailed setup guide",
            "troubleshooting.md": "Common issues and solutions",
            "api_reference.md": "API documentation"
        }
    }
}

print("CloudHSM PKCS#11 Project Structure:")
print("=" * 50)

def print_structure(structure, indent=0):
    for key, value in structure.items():
        print("  " * indent + "📁 " + key if key.endswith("/") else "  " * indent + "📄 " + key)
        if isinstance(value, dict):
            print_structure(value, indent + 1)
        else:
            print("  " * (indent + 1) + f"↳ {value}")

print_structure(project_structure)