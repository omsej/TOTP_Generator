import pyotp
import sys
from keystorage import load_totp_key, list_accounts

def generate_totp(account_name=None):
    """Generates a TOTP (Time-Based One-Time Password) for a specified account."""
    
    # If no account name is provided as an argument, prompt the user.
    if not account_name:
        accounts = list_accounts()
        
        # If no accounts are found, prompt the user to generate a key first.
        if not accounts:
            print("No accounts found. Please run otpkey.py first to generate and save a key.")
            return
        
        # Display available accounts and prompt user for selection.
        print("\nAvailable accounts:", accounts)
        account_name = input("\nEnter account name: ").strip()
    
    # Attempt to load the stored TOTP key for the specified account.
    key = load_totp_key(account_name)
    if not key:
        print(f"No TOTP key found for account: {account_name}")
        return

    # Generate a new TOTP code using the stored secret key.
    otp = pyotp.TOTP(key)
    otp_code = otp.now()

    # Display the generated OTP.
    print(f'\nTOTP for {account_name} is: {otp_code}')

if __name__ == "__main__":
    """Entry point for script execution. Checks for command-line arguments."""
    
    # Allows passing an account name as a command-line argument.
    account_name = sys.argv[1] if len(sys.argv) > 1 else None

    # Generate and display the OTP.
    generate_totp(account_name)
