# Secure Password Manager - User Guide

## Getting Started

### Installation

1. Clone the repository
2. Install dependencies with `npm install`
3. Start the application with `npm start`

The application will be available at http://localhost:3000

### Creating a Vault

1. When you first start the application, you'll be prompted to create a new vault
2. Choose a strong master password
   - The password strength meter will help you assess your password's security
   - Aim for at least a "Strong" rating
3. After creating the vault, you'll receive a recovery key
   - **Save this key securely** - it's the only way to recover your vault if you forget your master password
   - Store it in a physically secure location separate from your device

### Unlocking the Vault

1. Enter your master password
2. If you enter an incorrect password multiple times, the vault will temporarily lock as a security measure
3. After unlocking, your vault remains open until:
   - You manually lock it
   - You close the application
   - The auto-lock timeout occurs (5 minutes of inactivity by default)

## Managing Passwords

### Adding Passwords

1. Click "Add Password" button
2. Fill in the required information:
   - Name (required)
   - Username/Email
   - Password (required)
   - Website URL
   - Notes
   - Category (optional)
   - Tags (optional)
3. Click "Save"

### Generating Strong Passwords

1. When adding or editing a password, click "Generate Password"
2. Choose your generation options:
   - Length (8-128 characters)
   - Character types (uppercase, lowercase, numbers, symbols)
   - Exclude similar characters (like 1, l, I, 0, O)
   - Exclude specific characters
3. Alternatively, generate a passphrase:
   - Number of words (3-8)
   - Word separator
   - Capitalize words
   - Include numbers/symbols
4. Click "Use Password" to apply the generated password

### Viewing and Editing Passwords

1. Click on a password entry to view details
2. Password fields are hidden by default; click the eye icon to reveal
3. To edit, click the "Edit" button and modify the fields as needed
4. Click "Save" to update the entry

### Deleting Passwords

1. Select the password entry
2. Click the "Delete" button
3. Confirm deletion when prompted

### Organizing Passwords

1. Use categories to group related passwords
2. Add tags for additional organization
3. Use the search function to find passwords by name, username, website, or tags

## Security Features

### Password Strength Assessment

1. When adding or editing passwords, a strength meter shows the security level
2. Detailed feedback provides suggestions for improvement
3. The strength calculation uses entropy and pattern detection
4. Aim for "Strong" or "Very Strong" ratings for important accounts

### Data Breach Checking

1. Click "Check for Breaches" to verify if a password appears in known data breaches
2. You can check individual passwords or scan your entire vault
3. If compromised passwords are found, you'll receive recommendations to change them
4. Breach checking is done securely using k-anonymity (your passwords are never sent to external servers)

### Auto-Lock

1. Your vault automatically locks after 5 minutes of inactivity
2. You can manually lock the vault by clicking the "Lock" button
3. When locked, your master password is required to access your passwords

## Account Management

### Changing Master Password

1. Go to Settings
2. Click "Change Master Password"
3. Enter your current master password
4. Choose a new strong master password
5. After changing, you'll receive a new recovery key - save it securely

### Recovery Options

1. If you forget your master password, click "Recover Account"
2. Enter your recovery key
3. Create a new master password
4. Your vault will be unlocked, and you'll receive a new recovery key

## Security Best Practices

1. Use a strong, unique master password that you don't use elsewhere
2. Store your recovery key in a secure, offline location
3. Enable automatic breach checking
4. Regularly update important passwords
5. Use the strongest password possible for each website
6. Avoid reusing passwords across different websites
7. Lock your vault when not in use
8. Keep your device and software updated
9. Be cautious of phishing attempts
10. Consider using two-factor authentication when available on websites 