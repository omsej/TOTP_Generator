from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import json
import getpass

def get_encryption_key(password):
    # Derives an encryption key from a user-provided password using PBKDF2HMAC key derivation.
    
    # A fixed salt is used for simplicity, but in a real-world scenario,
    # a unique salt should be generated and securely stored for each encryption.
    salt = b'fixed_salt_value'  
    
    # Apply PBKDF2 (Password-Based Key Derivation Function 2) to strengthen password security.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Hashing algorithm
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,  # Increased iterations for better security
    )
    
    # Derive a key and encode it in base64 format for compatibility with Fernet.
    key = base64.b64encode(kdf.derive(password.encode()))
    return key

def save_totp_key(account_name, totp_key):
    # Encrypts and securely stores the TOTP key associated with the given account name.
    
    # Prompt user for their master password to encrypt the key.
    password = getpass.getpass("Enter master password: ")
    encryption_key = get_encryption_key(password)
    f = Fernet(encryption_key)

    # Attempt to load existing encrypted accounts; otherwise, create an empty dictionary.
    accounts = {}
    if os.path.exists('totp_keys.encrypted'):
        try:
            with open('totp_keys.encrypted', 'rb') as file:
                encrypted_data = file.read()
                decrypted_data = f.decrypt(encrypted_data)
                accounts = json.loads(decrypted_data)  # Convert JSON string back to a dictionary
        except Exception:
            print("Error: Wrong password or corrupted data")
            return  # Exit if decryption fails

    # Add new account and its associated TOTP key.
    accounts[account_name] = totp_key

    # Encrypt and save the updated accounts list.
    encrypted_data = f.encrypt(json.dumps(accounts).encode())  # Convert dictionary to JSON before encryption
    with open('totp_keys.encrypted', 'wb') as file:
        file.write(encrypted_data)

def load_totp_key(account_name):
    # Retrieves and decrypts the TOTP key for a specified account.
    
    # Return None if the encrypted storage file doesn't exist.
    if not os.path.exists('totp_keys.encrypted'):
        return None

    # Prompt user for the master password to decrypt stored keys.
    password = getpass.getpass("Enter master password: ")
    encryption_key = get_encryption_key(password)
    f = Fernet(encryption_key)

    try:
        with open('totp_keys.encrypted', 'rb') as file:
            encrypted_data = file.read()
            decrypted_data = f.decrypt(encrypted_data)  # Decrypt stored data
            accounts = json.loads(decrypted_data)  # Convert JSON string to dictionary

            # Return the TOTP key for the requested account (or None if not found).
            return accounts.get(account_name)
    except Exception:
        print("Error: Wrong password or corrupted data")
        return None

def list_accounts():
    # Lists all stored account names that have associated TOTP keys.
    
    # Return an empty list if no encrypted storage file is found.
    if not os.path.exists('totp_keys.encrypted'):
        return []
    
    # Prompt user for the master password to decrypt stored data.
    password = getpass.getpass("Enter master password: ")
    encryption_key = get_encryption_key(password)
    f = Fernet(encryption_key)

    try:
        with open('totp_keys.encrypted', 'rb') as file:
            encrypted_data = file.read()
            decrypted_data = f.decrypt(encrypted_data)  # Decrypt stored data
            accounts = json.loads(decrypted_data)  # Convert JSON string back to a dictionary
            
            # Return a list of stored account names.
            return list(accounts.keys())
    except Exception:
        print("Error: Wrong password or corrupted data")
        return []
