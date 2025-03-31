#!/usr/bin/env python3
"""
Wrapper script to run the Password Manager GUI
"""

import os
import sys
import subprocess

if __name__ == "__main__":
    # Get the current directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Run the main_gui.py script
    print("Starting Password Manager GUI...")
    try:
        subprocess.run([sys.executable, "src/main_gui.py"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running GUI: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nGUI terminated by user.")
        sys.exit(0) 