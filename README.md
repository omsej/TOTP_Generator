# TOTP Authentication Module

The **Time-based One-Time Password (TOTP) Generator** works in a similar way to Multi-Factor Authentication (MFA) apps on our phones. It generates time-sensitive authentication codes that can be used for secure logins.  

This project is **simplified** to help users understand the internal processes behind TOTP-based authentication. 
 

---

## Features
* Generates secure **TOTP keys**.
* Encrypts and securely stores keys using a **master password**.
* Retrieves and generates **time-sensitive OTPs** for stored accounts.
* Allows users to manage multiple accounts within the application.

---

## Encryption Process (Briefly):
**1. Key Derivation**

* The master password is processed using PBKDF2HMAC (SHA-256, 100,000 iterations) to generate a 32-byte encryption key.
* A fixed salt is used (which is a security limitation).

**2. Encrypting the Keys**

* The derived encryption key is used with Fernet to encrypt the TOTP keys.
* The encrypted data is stored in totp_keys.encrypted as a JSON dictionary.

**3. Decrypting the Keys**

* When retrieving a key, the user must enter the master password.
* The same PBKDF2 process regenerates the encryption key.
* The encrypted file is decrypted using Fernet.

## Security Considerations

A couple of suggested improvements if someone would like to improve the module in the future:
* The fixed salt reduces security; ideally, each user should have a unique salt.
* No password recovery mechanism means losing the master password makes all stored keys inaccessible.

---

## Installation
Ensure you have the required dependencies installed:
```sh
pip install -r requirements.txt
```

---

## Usage
**1. Initialize & Set a Master Password**
Before generating any TOTP keys, start by first creating a master password:
```
python setup.py
```
The password is used to decrypt and encrypt the stored keys. Currently there is no password recovery function.

**2. Generate a New TOTP Key for an Account**
To generate and store a new TOTP key:
```
python keygen.py
```
* You'll be prompted to enter an account name (e.g., "gmail" or "twitter").
* The program generates a Base32-encoded secret key and encrypts it.
* The key and account name are encrypted and saved to the "totp_keys.encrypted" file to later be retreived by otpapp.py.
* If you want, you can also save this key to an authenticator app on your phone and it will produce the same TOTP code.

**3. Retrieve a TOTP Code for an Account**
To generate a current TOTP code for a stored account:
```
python otpapp.py <account_name>
```
If you don’t provide an account name, you will be prompted to select from stored accounts.

---

## Example Workflow
1. Set up encryption storage → python setup.py
2. Generate a new key for an account → python keygen.py
3. Retrieve a TOTP code → python otpapp.py account_name
4. Use the generated OTP to authenticate where needed.
