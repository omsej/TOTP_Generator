from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import json
import getpass

def create_master_password():
    """Prompts the user to create a master password for encrypting stored TOTP keys."""
    
    while True:
        # Prompt user for password and confirmation
        password = getpass.getpass("Create your master password: ")
        confirm = getpass.getpass("Confirm your master password: ")
        
        # Ensure passwords match
        if password != confirm:
            print("Passwords don't match. Please try again.")
            continue
            
        # Enforce a minimum password length
        if len(password) < 8:
            print("Password must be at least 8 characters long. Please try again.")
            continue
            
        # Generate an encryption key from the provided password
        encryption_key = get_encryption_key(password)
        f = Fernet(encryption_key)

        # Encrypt an empty dictionary (to initialize storage)
        encrypted_data = f.encrypt(json.dumps({}).encode())
        
        # Save the encrypted empty storage file
        with open('totp_keys.encrypted', 'wb') as file:
            file.write(encrypted_data)
            
        print("\nMaster password created successfully!")
        print("Use this password when running keygen.py or otpapp.py")
        break

def get_encryption_key(password):
    """Derives a secure encryption key from the provided password using PBKDF2HMAC."""
    
    # Uses a fixed salt; ideally, this should be unique per user and stored securely.
    salt = b'fixed_salt_value'  
    
    # Key derivation function (PBKDF2 with SHA-256 and 100,000 iterations for added security)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit encryption key
        salt=salt,
        iterations=100000,
    )
    
    # Encode the derived key in Base64 for compatibility with Fernet encryption
    key = base64.b64encode(kdf.derive(password.encode()))
    return key

if __name__ == "__main__":
    """Script entry point - initializes the encryption system by setting up the master password."""
    
    # Check if an encrypted storage file already exists
    if os.path.exists('totp_keys.encrypted'):
        print("Storage file already exists!")
        
        # Prompt user to confirm if they want to reset the storage
        choice = input("Do you want to reset and create a new master password? (y/N): ")
        if choice.lower() != 'y':
            print("Exiting without changes.")
            exit()
    
    # Proceed with master password creation
    create_master_password()
