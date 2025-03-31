# Security Implementation Details

This document describes the security implementation details of the password manager.

## Encryption

### AES-256-GCM

The password manager uses AES-256 in Galois/Counter Mode (GCM) for encrypting vault data. GCM provides both confidentiality and authenticity, meaning it can detect if the ciphertext has been tampered with.

- Key size: 256 bits (32 bytes)
- IV size: 96 bits (12 bytes)
- Auth tag size: 128 bits (16 bytes)

Each encrypted item contains:
- The encrypted data
- The initialization vector (IV)
- The authentication tag

### PBKDF2 Key Derivation

The master password is never stored directly. Instead, it's used to derive encryption keys using PBKDF2:

- Iterations: 600,000
- Hash function: SHA-512
- Salt size: 256 bits (32 bytes)
- Output key size: 256 bits (32 bytes)

The high iteration count makes brute-force attacks computationally expensive.

### Argon2id Password Hashing

For master password authentication, we use Argon2id, which is resistant to both GPU and side-channel attacks:

- Memory cost: 64 MB
- Time cost: 3 iterations
- Parallelism: 1
- Hash length: 32 bytes

## Zero-Knowledge Architecture

The password manager implements a zero-knowledge architecture where:

1. All encryption and decryption occur locally on the device
2. The master password is never sent to any server
3. The server only stores encrypted data that can't be decrypted without the master password
4. Even database administrators cannot access unencrypted user data

## Memory Security

To protect sensitive data in memory:

1. Encryption keys are securely wiped from memory when no longer needed
2. The vault automatically locks after a period of inactivity (default: 5 minutes)
3. Memory is overwritten with zeros when clearing sensitive data

## Master Password Protection

The master password is protected by:

1. Limiting failed login attempts to prevent brute force attacks
2. Requiring strong passwords with a minimum entropy score
3. Using Argon2id for password hashing

## Breach Checking

Password breach checking uses a k-anonymity model to securely check passwords against known data breaches:

1. The password is hashed using SHA-1 (for compatibility with the HIBP API only)
2. Only the first 5 characters of the hash are sent to the API
3. The API returns all matching hashes with the same prefix
4. The client checks if the full hash exists in the returned list
5. The actual password is never transmitted

## Recovery Options

The password manager provides secure recovery options:

1. A randomly generated recovery key (32 bytes encoded in base64)
2. The recovery key encrypts a backup of the vault key
3. Security questions with answers hashed using Argon2id

## Secure Design Principles

The implementation follows these security principles:

1. Defense in depth - Multiple layers of security
2. Least privilege - Components only have access to what they need
3. Fail securely - Errors don't compromise security
4. Complete mediation - All access to objects is checked for authorization
5. Psychological acceptability - Security mechanisms are user-friendly
6. Open design - Security doesn't rely on obscurity

## Security Test Coverage

The security implementation is verified by comprehensive tests covering:

1. Encryption and decryption functionality
2. Key derivation functions
3. Password hashing and verification
4. Memory wiping functions
5. Breach checking mechanisms
6. Password strength analysis
7. Recovery mechanisms 