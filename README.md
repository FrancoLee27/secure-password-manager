# Secure Password Manager

A zero-knowledge, secure password management solution featuring strong encryption, breach checking, and password strength analysis.

## Features

- Secure password storage with strong encryption
- Password strength analysis
- Breach checking to identify compromised passwords
- Password generation with configurable options
- Multi-platform GUI interface with Tkinter
- Cloud synchronization capability
- Auto-lock for security

## Installation

1. Clone this repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   ./launch_gui.py
   ```

## Usage

The application provides both a full-featured GUI and a simplified version:

- For the full GUI: `./launch_gui.py`
- For the simplified GUI: `./run_simple_gui.py`
- With debug output: `./launch_gui.py --debug`

## Security

- All passwords are encrypted using strong AES-256 encryption
- Master password is never stored, only a derived key is used
- Auto-lock feature protects your data when you're away
- Zero-knowledge design means your data remains private even during synchronization

## License

MIT License 