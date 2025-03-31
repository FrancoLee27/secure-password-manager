#!/usr/bin/env python3
"""
Unified launcher for the Password Manager GUI
Provides proper import paths and graceful error handling
"""

import os
import sys
import subprocess
import traceback
import platform

def setup_environment():
    """Set up the Python environment for GUI execution"""
    # Get project root directory
    root_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Add the root directory to Python path to resolve imports
    sys.path.insert(0, root_dir)
    
    # Set environment variables
    os.environ['PM_ROOT'] = root_dir
    
    return root_dir

def run_full_gui():
    """Try to run the full-featured GUI"""
    try:
        # First attempt to import and run the full GUI
        from src.ui.gui import PasswordManagerGUI
        import tkinter as tk
        
        print("Starting full-featured Password Manager GUI...")
        root = tk.Tk()
        app = PasswordManagerGUI(root)
        root.mainloop()
        return True
    except ImportError as e:
        print(f"Could not load full GUI: {e}")
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"Error running full GUI: {e}")
        traceback.print_exc()
        return False

def run_simple_gui():
    """Run the simple GUI as fallback"""
    try:
        # Fall back to the simple GUI
        from src.ui.simple_gui import SimplePasswordManagerGUI
        import tkinter as tk
        
        print("Starting simplified Password Manager GUI...")
        root = tk.Tk()
        app = SimplePasswordManagerGUI(root)
        root.mainloop()
        return True
    except ImportError as e:
        print(f"Could not load simple GUI: {e}")
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"Error running simple GUI: {e}")
        traceback.print_exc()
        return False

def run_external_command():
    """Run GUI as an external process with proper environment"""
    try:
        # Set up environment for subprocess
        env = os.environ.copy()
        root_dir = os.path.dirname(os.path.abspath(__file__))
        
        if 'PYTHONPATH' in env:
            env['PYTHONPATH'] = f"{root_dir}{os.pathsep}{env['PYTHONPATH']}"
        else:
            env['PYTHONPATH'] = root_dir
        
        print("Launching GUI as external process...")
        cmd = [sys.executable, "-m", "src.ui.simple_gui"]
        subprocess.run(cmd, env=env, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"External process error: {e}")
        return False
    except Exception as e:
        print(f"Failed to launch GUI externally: {e}")
        traceback.print_exc()
        return False

def show_banner():
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

def show_system_info():
    """Show system information for debugging"""
    print(f"Python version: {sys.version}")
    print(f"Platform: {platform.platform()}")
    print(f"Working directory: {os.getcwd()}")
    print(f"Python path: {sys.path}")
    print(f"Environment PYTHONPATH: {os.environ.get('PYTHONPATH', 'Not set')}")
    print("-" * 50)

def main():
    """Main entry point"""
    show_banner()
    
    # Set up environment variables and paths
    root_dir = setup_environment()
    
    # Show debugging information
    if '--debug' in sys.argv:
        show_system_info()
    
    # Try running methods in order until one works
    if run_full_gui():
        return 0
    
    print("\nFalling back to simple GUI...\n")
    if run_simple_gui():
        return 0
    
    print("\nTrying external process approach...\n")
    if run_external_command():
        return 0
    
    print("\nAll GUI launch methods failed.")
    return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nApplication terminated by user.")
        sys.exit(0) 