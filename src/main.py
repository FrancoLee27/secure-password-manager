#!/usr/bin/env python3
"""
Secure Password Manager
Main entry point for the application.
"""

import sys
import os
import traceback

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ui.cli import PasswordManagerCLI


def show_intro():
    """Display introduction message"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║            🔒 SECURE PASSWORD MANAGER 🔒                     ║
║                                                               ║
║  A zero-knowledge, secure password management solution        ║
║  featuring strong encryption, breach checking, and            ║
║  password strength analysis.                                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)


def main():
    """Main application entry point"""
    try:
        show_intro()
        cli = PasswordManagerCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\nApplication terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main() 