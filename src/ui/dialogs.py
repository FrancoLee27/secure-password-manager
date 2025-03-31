"""
Dialog windows for the Password Manager GUI.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import uuid
from datetime import datetime

# Add the project root to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(parent_dir)
sys.path.insert(0, root_dir)

# Fix imports to point to correct modules
from src.password.generator import generate_password  # Changed from crypto
from src.password.strength import analyze_password  # Changed from crypto.password_analyzer


class PasswordEntryDialog:
    """Dialog for adding or editing a password entry"""
    
    def __init__(self, parent, vault_manager, entry_id=None, title="Add Password Entry"):
        """Initialize the dialog"""
        self.parent = parent
        self.vault_manager = vault_manager
        self.entry_id = entry_id
        self.result = None
        
        # Create the dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("500x500")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f"+{x}+{y}")
        
        # Create the form
        self.create_form()
        
        # Load entry data if editing
        if entry_id:
            self.load_entry_data()
        
        # Set dialog modal
        self.dialog.focus_set()
        self.dialog.wait_window()
    
    def create_form(self):
        """Create the form elements"""
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title field
        title_label = ttk.Label(main_frame, text="Title:")
        title_label.grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.title_var = tk.StringVar()
        title_entry = ttk.Entry(main_frame, textvariable=self.title_var, width=40)
        title_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        title_entry.focus_set()
        
        # Username field
        username_label = ttk.Label(main_frame, text="Username:")
        username_label.grid(row=1, column=0, sticky=tk.W, pady=5)
        
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(main_frame, textvariable=self.username_var, width=40)
        username_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Password field
        password_label = ttk.Label(main_frame, text="Password:")
        password_label.grid(row=2, column=0, sticky=tk.W, pady=5)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, width=40, show="•")
        self.password_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Password controls
        pwd_control_frame = ttk.Frame(main_frame)
        pwd_control_frame.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        self.show_password_var = tk.BooleanVar()
        show_pwd_check = ttk.Checkbutton(
            pwd_control_frame, 
            text="Show Password", 
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        show_pwd_check.pack(side=tk.LEFT, padx=5)
        
        generate_btn = ttk.Button(pwd_control_frame, text="Generate", command=self.generate_password)
        generate_btn.pack(side=tk.LEFT, padx=5)
        
        # URL field
        url_label = ttk.Label(main_frame, text="URL:")
        url_label.grid(row=4, column=0, sticky=tk.W, pady=5)
        
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(main_frame, textvariable=self.url_var, width=40)
        url_entry.grid(row=4, column=1, sticky=tk.W, pady=5)
        
        # Notes field
        notes_label = ttk.Label(main_frame, text="Notes:")
        notes_label.grid(row=5, column=0, sticky=tk.NW, pady=5)
        
        self.notes_text = tk.Text(main_frame, width=38, height=8)
        self.notes_text.grid(row=5, column=1, sticky=tk.W, pady=5)
        
        # Password strength meter
        strength_label = ttk.Label(main_frame, text="Strength:")
        strength_label.grid(row=6, column=0, sticky=tk.W, pady=5)
        
        self.strength_frame = ttk.Frame(main_frame)
        self.strength_frame.grid(row=6, column=1, sticky=tk.W, pady=5)
        
        self.strength_var = tk.StringVar()
        self.strength_var.set("N/A")
        
        strength_text = ttk.Label(self.strength_frame, textvariable=self.strength_var)
        strength_text.pack(side=tk.LEFT, padx=5)
        
        self.strength_meter = ttk.Progressbar(self.strength_frame, length=200, mode="determinate")
        self.strength_meter.pack(side=tk.LEFT, padx=5)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=7, column=0, columnspan=2, pady=20)
        
        save_btn = ttk.Button(btn_frame, text="Save", command=self.save_entry)
        save_btn.pack(side=tk.LEFT, padx=5)
        
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.dialog.destroy)
        cancel_btn.pack(side=tk.LEFT, padx=5)
        
        # Bind password change to update strength meter
        self.password_var.trace_add("write", self.update_strength_meter)
    
    def load_entry_data(self):
        """Load entry data if editing"""
        if not self.entry_id:
            return
            
        # Get entry data
        result = self.vault_manager.get_password(self.entry_id)
        if not result['success']:
            messagebox.showerror("Error", result.get('message', "Failed to load entry"))
            self.dialog.destroy()
            return
            
        entry = result['entry']
        
        # Set form values
        self.title_var.set(entry.get('title', ''))
        self.username_var.set(entry.get('username', ''))
        self.password_var.set(entry.get('password', ''))
        self.url_var.set(entry.get('url', ''))
        
        # Set notes
        if 'notes' in entry:
            self.notes_text.delete(1.0, tk.END)
            self.notes_text.insert(tk.END, entry['notes'])
        
        # Update strength meter
        self.update_strength_meter()
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def generate_password(self):
        """Generate a random password"""
        password = generate_password()
        self.password_var.set(password)
        self.update_strength_meter()
    
    def update_strength_meter(self, *args):
        """Update the password strength meter"""
        password = self.password_var.get()
        if not password:
            self.strength_var.set("N/A")
            self.strength_meter['value'] = 0
            return
            
        # Analyze password
        analysis = analyze_password(password)
        strength = analysis['strength']
        
        # Update meter
        self.strength_var.set(f"{strength['label']} ({strength['score']}/100)")
        self.strength_meter['value'] = strength['score']
    
    def save_entry(self):
        """Save the entry"""
        # Get form values
        title = self.title_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        url = self.url_var.get().strip()
        notes = self.notes_text.get(1.0, tk.END).strip()
        
        # Validate
        if not title:
            messagebox.showerror("Error", "Title is required")
            return
            
        if not password:
            messagebox.showerror("Error", "Password is required")
            return
        
        # Create entry data
        entry = {
            'title': title,
            'username': username,
            'password': password,
            'url': url,
            'notes': notes
        }
        
        # Add strength info
        analysis = analyze_password(password)
        entry['strength'] = analysis['strength']
        
        # Save entry
        if self.entry_id:
            # Update existing entry
            entry['id'] = self.entry_id
            result = self.vault_manager.update_password(entry)
        else:
            # Add new entry
            entry['id'] = str(uuid.uuid4())
            entry['created_at'] = datetime.now().isoformat()
            entry['updated_at'] = entry['created_at']
            result = self.vault_manager.add_password(entry)
        
        if result['success']:
            self.result = entry
            self.dialog.destroy()
        else:
            messagebox.showerror("Error", result.get('message', "Failed to save entry"))


class SyncConfigDialog:
    """Dialog for configuring cloud synchronization"""
    
    def __init__(self, parent, cloud_sync):
        """Initialize the dialog"""
        self.parent = parent
        self.cloud_sync = cloud_sync
        self.result = None
        
        # Create the dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Configure Synchronization")
        self.dialog.geometry("400x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f"+{x}+{y}")
        
        # Create the form
        self.create_form()
        
        # Load current settings
        self.load_settings()
        
        # Set dialog modal
        self.dialog.focus_set()
        self.dialog.wait_window()
    
    def create_form(self):
        """Create the form elements"""
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Server URL field
        server_label = ttk.Label(main_frame, text="Server URL:")
        server_label.grid(row=0, column=0, sticky=tk.W, pady=10)
        
        self.server_var = tk.StringVar()
        server_entry = ttk.Entry(main_frame, textvariable=self.server_var, width=30)
        server_entry.grid(row=0, column=1, sticky=tk.W, pady=10)
        
        # Use mock server
        self.mock_server_var = tk.BooleanVar()
        mock_check = ttk.Checkbutton(
            main_frame, 
            text="Use mock server mode (for testing)", 
            variable=self.mock_server_var,
            command=self.toggle_mock_server
        )
        mock_check.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Information text
        info_text = tk.Text(main_frame, width=35, height=6, wrap=tk.WORD)
        info_text.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=10)
        info_text.insert(tk.END, 
            "To use real server synchronization, enter the server URL (e.g., http://localhost:5005).\n\n"
            "For offline testing, use mock server mode which simulates "
            "synchronization without an actual server."
        )
        info_text.config(state=tk.DISABLED)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        save_btn = ttk.Button(btn_frame, text="Save", command=self.save_config)
        save_btn.pack(side=tk.LEFT, padx=5)
        
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.dialog.destroy)
        cancel_btn.pack(side=tk.LEFT, padx=5)
    
    def load_settings(self):
        """Load current sync settings"""
        status = self.cloud_sync.get_sync_status()
        
        # Set server URL
        if status.get('configured'):
            api_url = self.cloud_sync.sync_metadata.get('api_url', '')
            
            if api_url == 'mock://server':
                self.mock_server_var.set(True)
                self.server_var.set('')
            else:
                self.mock_server_var.set(False)
                self.server_var.set(api_url)
    
    def toggle_mock_server(self):
        """Toggle mock server mode"""
        if self.mock_server_var.get():
            self.server_var.set('')
    
    def save_config(self):
        """Save the configuration"""
        if self.mock_server_var.get():
            # Use mock server
            api_url = 'mock://server'
        else:
            # Use real server
            api_url = self.server_var.get().strip()
            if not api_url:
                messagebox.showerror("Error", "Please enter a server URL or use mock server mode")
                return
        
        # Save configuration
        result = self.cloud_sync.configure_sync(api_url)
        
        if result:
            self.result = api_url
            self.dialog.destroy()
        else:
            messagebox.showerror("Error", "Failed to save configuration")


class SyncStatusDialog:
    """Dialog for viewing synchronization status"""
    
    def __init__(self, parent, cloud_sync):
        """Initialize the dialog"""
        self.parent = parent
        self.cloud_sync = cloud_sync
        
        # Create the dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Synchronization Status")
        self.dialog.geometry("400x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f"+{x}+{y}")
        
        # Create the form
        self.create_form()
        
        # Load status
        self.load_status()
        
        # Set dialog modal
        self.dialog.focus_set()
        self.dialog.wait_window()
    
    def create_form(self):
        """Create the form elements"""
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status labels
        ttk.Label(main_frame, text="Sync Status", font=("Helvetica", 14, "bold")).grid(
            row=0, column=0, columnspan=2, sticky=tk.W, pady=10
        )
        
        # Configure status
        ttk.Label(main_frame, text="Configured:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.configured_var = tk.StringVar()
        ttk.Label(main_frame, textvariable=self.configured_var).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Server URL
        ttk.Label(main_frame, text="Server URL:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.server_var = tk.StringVar()
        ttk.Label(main_frame, textvariable=self.server_var).grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Authentication status
        ttk.Label(main_frame, text="Authenticated:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.auth_var = tk.StringVar()
        ttk.Label(main_frame, textvariable=self.auth_var).grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Last push
        ttk.Label(main_frame, text="Last Push:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.push_var = tk.StringVar()
        ttk.Label(main_frame, textvariable=self.push_var).grid(row=4, column=1, sticky=tk.W, pady=5)
        
        # Last pull
        ttk.Label(main_frame, text="Last Pull:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.pull_var = tk.StringVar()
        ttk.Label(main_frame, textvariable=self.pull_var).grid(row=5, column=1, sticky=tk.W, pady=5)
        
        # Client ID
        ttk.Label(main_frame, text="Client ID:").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.client_var = tk.StringVar()
        ttk.Label(main_frame, textvariable=self.client_var).grid(row=6, column=1, sticky=tk.W, pady=5)
        
        # Mock mode
        ttk.Label(main_frame, text="Mock Mode:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.mock_var = tk.StringVar()
        ttk.Label(main_frame, textvariable=self.mock_var).grid(row=7, column=1, sticky=tk.W, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=8, column=0, columnspan=2, pady=20)
        
        close_btn = ttk.Button(btn_frame, text="Close", command=self.dialog.destroy)
        close_btn.pack(side=tk.LEFT, padx=5)
        
        refresh_btn = ttk.Button(btn_frame, text="Refresh", command=self.load_status)
        refresh_btn.pack(side=tk.LEFT, padx=5)
    
    def load_status(self):
        """Load current sync status"""
        status = self.cloud_sync.get_sync_status()
        
        # Set status values
        self.configured_var.set("Yes" if status.get('configured') else "No")
        
        api_url = self.cloud_sync.sync_metadata.get('api_url', 'Not configured')
        self.server_var.set(api_url)
        
        self.auth_var.set("Yes" if status.get('authenticated') else "No")
        self.push_var.set(status.get('last_push', 'Never'))
        self.pull_var.set(status.get('last_pull', 'Never'))
        self.client_var.set(status.get('client_id', 'N/A'))
        self.mock_var.set("Yes" if api_url == 'mock://server' else "No") 