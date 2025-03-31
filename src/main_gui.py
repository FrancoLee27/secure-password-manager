#!/usr/bin/env python3
"""
Main entry point for the Secure Password Manager GUI.
"""

import os
import sys
import tkinter as tk
import traceback

# Add the parent directory to the Python path so we can import from src
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# Now we can import using the src package
from src.ui.gui import PasswordManagerGUI


def show_intro():
    """Show the application banner"""
    print("\n" + "╔═" + "═" * 47 + "═╗")
    print("║ " + " " * 47 + " ║")
    print("║ " + "         🔒 SECURE PASSWORD MANAGER 🔒" + "          ║")
    print("║ " + " " * 47 + " ║")
    print("║ " + "  A zero-knowledge, secure password management solution" + "        ║")
    print("║ " + "  featuring strong encryption, breach checking, and" + "            ║")
    print("║ " + "  password strength analysis." + "                                  ║")
    print("║ " + " " * 47 + " ║")
    print("╚═" + "═" * 47 + "═╝")
    print("    ")


def main():
    """Main application entry point"""
    try:
        show_intro()
        root = tk.Tk()
        app = PasswordManagerGUI(root)
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main() 