import secrets
import base64
from keystorage import save_totp_key, list_accounts

# OTP utilizes Base32-encoded keys which converts every 5 bytes into 8 characters.
# To determine the required bytes for a key: (5/8) * 32 = 20 bytes.
# (Each 8-character block represents 5 bytes, multiplied by the desired key length).
def generate_secret_key(byte_length=20):
    # Generate a random base32 encoded secret key
    random_bytes = secrets.token_bytes(byte_length)
    
    # Encode the byte sequence in Base32 and return as a string.
    encoded_key = base64.b32encode(random_bytes).decode()
    return encoded_key

def main():
    # Display existing accounts stored in keystorage.
    print("\nExisting accounts:", list_accounts())
    # Prompt user for the new account name.
    account_name = input("\nEnter account name (e.g., 'gmail' or 'twitter'): ").strip()
    
    if not account_name:
        print("Account name cannot be empty")
        return
    
    # Generate new key
    key = generate_secret_key()
    
    # Save encrypted key with account name
    save_totp_key(account_name, key)
    
    # Display confirmation and the generated key.
    print("\nGenerated and saved new TOTP key for", account_name)
    print("Key (save this somewhere safe):", key)

if __name__ == "__main__":
    main()
