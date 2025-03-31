#!/usr/bin/env python3
"""
Launcher for the Password Manager GUI
This script sets up the environment and launches the GUI with proper imports
"""

import os
import sys
import subprocess

def main():
    """Main function to launch the GUI"""
    # Get the current directory (project root)
    root_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Set the PYTHONPATH environment variable to include the project root
    env = os.environ.copy()
    if 'PYTHONPATH' in env:
        env['PYTHONPATH'] = f"{root_dir}{os.pathsep}{env['PYTHONPATH']}"
    else:
        env['PYTHONPATH'] = root_dir
    
    # Construct the command to launch the GUI
    cmd = [sys.executable, "-m", "src.ui.simple_gui"]
    
    # Print debug information
    print(f"Launching GUI from: {root_dir}")
    print(f"With PYTHONPATH: {env['PYTHONPATH']}")
    print(f"Command: {' '.join(cmd)}")
    
    # Launch the GUI
    try:
        result = subprocess.run(cmd, env=env, check=True)
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"Error launching GUI: {e}", file=sys.stderr)
        return e.returncode
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        return 130  # Standard exit code for Ctrl+C

if __name__ == "__main__":
    sys.exit(main()) 