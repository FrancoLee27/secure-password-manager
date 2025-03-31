"""
Simple GUI for the Password Manager
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import uuid
from datetime import datetime

# Add project root to path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(parent_dir)
sys.path.insert(0, root_dir)

try:
    # Try to import the real components
    from src.password.vault import VaultManager
    from src.password.generator import generate_password
    from src.password.strength import analyze_password
    USING_MOCK = False
except ImportError:
    # Fall back to mock implementations
    USING_MOCK = True
    
    class MockVaultManager:
        def __init__(self):
            self.unlocked = False
            self.auto_lock_timeout = 300
            self.passwords = []
            
        def unlock(self, password):
            self.unlocked = True
            return {'success': True}
            
        def create_user(self, username, password):
            self.unlocked = True
            return {'success': True}
            
        def get_all_passwords(self):
            return {'success': True, 'entries': self.passwords}
            
        def add_password(self, entry):
            self.passwords.append(entry)
            return {'success': True, 'id': entry.get('id')}
            
        def lock(self):
            self.unlocked = False
            return {'success': True}
    
    def generate_password(options=None):
        return "Password123!@#"
        
    def analyze_password(password):
        return {'score': 3, 'strength': 'Strong', 'feedback': 'Good password!'}
    
    VaultManager = MockVaultManager


class SimplePasswordManagerGUI:
    """A simple version of the Password Manager GUI"""
    
    def __init__(self, root):
        """Initialize the GUI"""
        self.root = root
        self.root.title("Simple Password Manager")
        self.root.geometry("800x600")
        
        # Create vault manager
        self.vault_manager = VaultManager()
        
        # Create login frame
        self.login_frame = ttk.Frame(self.root, padding=20)
        
        # Title
        title_label = ttk.Label(
            self.login_frame, 
            text="🔒 Password Manager", 
            font=("Helvetica", 20, "bold")
        )
        title_label.pack(pady=20)
        
        # Password field
        password_frame = ttk.Frame(self.login_frame)
        password_frame.pack(pady=20, fill=tk.X)
        
        password_label = ttk.Label(password_frame, text="Master Password:")
        password_label.pack(anchor=tk.W)
        
        self.password_entry = ttk.Entry(password_frame, show="•", width=30)
        self.password_entry.pack(fill=tk.X, pady=5)
        self.password_entry.bind("<Return>", lambda e: self.login())
        
        # Buttons
        btn_frame = ttk.Frame(self.login_frame)
        btn_frame.pack(pady=20)
        
        login_btn = ttk.Button(btn_frame, text="Unlock Vault", command=self.login)
        login_btn.pack(side=tk.LEFT, padx=5)
        
        create_btn = ttk.Button(btn_frame, text="Create New Vault", command=self.create_vault)
        create_btn.pack(side=tk.LEFT, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.login_frame, textvariable=self.status_var, font=("Helvetica", 10))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
        
        # Set focus to password entry
        self.password_entry.focus_set()
        
        # Show login frame initially
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create main frame but don't show it yet
        self.create_main_frame()
    
    def create_main_frame(self):
        """Create the main application frame"""
        self.main_frame = ttk.Frame(self.root, padding=20)
        
        # Title
        title_label = ttk.Label(
            self.main_frame, 
            text="Password Manager - Vault", 
            font=("Helvetica", 16, "bold")
        )
        title_label.pack(pady=10)
        
        # Toolbar
        toolbar = ttk.Frame(self.main_frame)
        toolbar.pack(side=tk.TOP, fill=tk.X, pady=10)
        
        add_btn = ttk.Button(toolbar, text="Add Password", command=self.add_password)
        add_btn.pack(side=tk.LEFT, padx=5)
        
        generate_btn = ttk.Button(toolbar, text="Generate Password", command=self.generate_password)
        generate_btn.pack(side=tk.LEFT, padx=5)
        
        # Password list
        list_frame = ttk.Frame(self.main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create Treeview for password list
        columns = ("title", "username", "url", "created", "strength")
        self.password_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        
        # Define headings
        self.password_tree.heading("title", text="Title")
        self.password_tree.heading("username", text="Username")
        self.password_tree.heading("url", text="URL")
        self.password_tree.heading("created", text="Created")
        self.password_tree.heading("strength", text="Strength")
        
        # Define columns
        self.password_tree.column("title", width=150)
        self.password_tree.column("username", width=150)
        self.password_tree.column("url", width=150)
        self.password_tree.column("created", width=100)
        self.password_tree.column("strength", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.password_tree.yview)
        self.password_tree.configure(yscroll=scrollbar.set)
        
        # Pack elements
        self.password_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click event
        self.password_tree.bind("<Double-1>", self.on_entry_double_click)
        
        # Bottom buttons
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
        
        lock_btn = ttk.Button(btn_frame, text="Lock Vault", command=self.lock_vault)
        lock_btn.pack(side=tk.LEFT, padx=5)
        
        exit_btn = ttk.Button(btn_frame, text="Exit", command=self.root.quit)
        exit_btn.pack(side=tk.RIGHT, padx=5)
        
        # Status bar
        status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, font=("Helvetica", 10))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=5)
    
    def login(self):
        """Handle login"""
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
            
        self.status_var.set("Unlocking vault...")
        self.root.update()
        
        # Try to unlock
        result = self.vault_manager.unlock(password)
        if result['success']:
            self.show_main_screen()
            self.status_var.set("Vault unlocked successfully")
        else:
            messagebox.showerror("Error", result.get('message', "Failed to unlock vault"))
            self.status_var.set("Ready")
        
        # Clear password field
        self.password_entry.delete(0, tk.END)
    
    def create_vault(self):
        """Create a new vault"""
        # Get username and password
        username = simpledialog.askstring("Create Vault", "Enter username:")
        if not username:
            return
            
        password = simpledialog.askstring("Create Vault", "Enter master password:", show="•")
        if not password:
            return
            
        confirm = simpledialog.askstring("Create Vault", "Confirm master password:", show="•")
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        self.status_var.set("Creating vault...")
        self.root.update()
        
        # Create vault
        result = self.vault_manager.create_user(username, password)
        if result['success']:
            messagebox.showinfo("Success", "Vault created successfully")
            self.show_main_screen()
            self.status_var.set("Vault created and unlocked")
        else:
            messagebox.showerror("Error", result.get('message', "Failed to create vault"))
            self.status_var.set("Ready")
    
    def show_main_screen(self):
        """Show the main application screen"""
        # Hide login frame
        self.login_frame.pack_forget()
        
        # Show main frame
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Load passwords
        self.load_passwords()
    
    def load_passwords(self):
        """Load passwords into the treeview"""
        # Clear existing items
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
            
        if not self.vault_manager.unlocked:
            return
            
        # Get passwords
        result = self.vault_manager.get_all_passwords()
        if result['success']:
            entries = result['entries']
            for entry in entries:
                # Format date
                created = entry.get('created_at', '').split('T')[0] if 'created_at' in entry else ''
                
                # Get strength
                strength = entry.get('strength', {}).get('label', 'N/A')
                
                # Add to tree
                self.password_tree.insert(
                    "", tk.END,
                    values=(
                        entry.get('title', ''),
                        entry.get('username', ''),
                        entry.get('url', ''),
                        created,
                        strength
                    ),
                    tags=(entry.get('id', ''),)
                )
    
    def add_password(self):
        """Add a new password"""
        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Password")
        dialog.geometry("400x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Create form
        form = ttk.Frame(dialog, padding=20)
        form.pack(fill=tk.BOTH, expand=True)
        
        # Title field
        ttk.Label(form, text="Title:").grid(row=0, column=0, sticky=tk.W, pady=5)
        title_var = tk.StringVar()
        ttk.Entry(form, textvariable=title_var, width=30).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Username field
        ttk.Label(form, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        username_var = tk.StringVar()
        ttk.Entry(form, textvariable=username_var, width=30).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Password field
        ttk.Label(form, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(form, textvariable=password_var, width=30, show="•")
        password_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Password visibility toggle
        show_password_var = tk.BooleanVar()
        ttk.Checkbutton(
            form, 
            text="Show Password", 
            variable=show_password_var,
            command=lambda: password_entry.config(show="" if show_password_var.get() else "•")
        ).grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Generate password button
        ttk.Button(
            form, 
            text="Generate Password",
            command=lambda: password_var.set(generate_password())
        ).grid(row=4, column=1, sticky=tk.W, pady=5)
        
        # URL field
        ttk.Label(form, text="URL:").grid(row=5, column=0, sticky=tk.W, pady=5)
        url_var = tk.StringVar()
        ttk.Entry(form, textvariable=url_var, width=30).grid(row=5, column=1, sticky=tk.W, pady=5)
        
        # Notes field
        ttk.Label(form, text="Notes:").grid(row=6, column=0, sticky=tk.NW, pady=5)
        notes_text = tk.Text(form, width=30, height=5)
        notes_text.grid(row=6, column=1, sticky=tk.W, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(form)
        btn_frame.grid(row=7, column=0, columnspan=2, pady=10)
        
        def save_entry():
            # Get values
            title = title_var.get().strip()
            username = username_var.get().strip()
            password = password_var.get()
            url = url_var.get().strip()
            notes = notes_text.get(1.0, tk.END).strip()
            
            # Validate
            if not title:
                messagebox.showerror("Error", "Title is required")
                return
                
            if not password:
                messagebox.showerror("Error", "Password is required")
                return
            
            # Analyze password
            analysis = analyze_password(password)
            
            # Create entry
            entry = {
                'id': str(uuid.uuid4()),
                'title': title,
                'username': username,
                'password': password,
                'url': url,
                'notes': notes,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'strength': analysis
            }
            
            # Add entry
            result = self.vault_manager.add_password(entry)
            if result['success']:
                dialog.destroy()
                self.status_var.set("Password added successfully")
                self.load_passwords()
            else:
                messagebox.showerror("Error", result.get('message', "Failed to add password"))
        
        ttk.Button(btn_frame, text="Save", command=save_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def on_entry_double_click(self, event):
        """Handle double-click on password entry"""
        # Get selected item
        selected = self.password_tree.selection()
        if not selected:
            return
        
        # Get entry ID
        entry_id = self.password_tree.item(selected[0], "tags")[0]
        
        # For the simple GUI, just show the password
        messagebox.showinfo("Password", f"Would show password for entry {entry_id}")
    
    def generate_password(self):
        """Generate and display a random password"""
        password = generate_password()
        
        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Generated Password")
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Add content
        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Generated Password:", font=("Helvetica", 12)).pack(pady=5)
        
        password_var = tk.StringVar(value=password)
        password_entry = ttk.Entry(frame, textvariable=password_var, width=30, font=("Courier", 12))
        password_entry.pack(pady=10)
        password_entry.select_range(0, tk.END)
        password_entry.focus_set()
        
        # Analyze password
        analysis = analyze_password(password)
        strength = analysis['strength']
        
        ttk.Label(frame, text=f"Strength: {strength}").pack(pady=5)
        
        # Add buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        
        def copy_to_clipboard():
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard")
        
        ttk.Button(btn_frame, text="Copy to Clipboard", command=copy_to_clipboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def lock_vault(self):
        """Lock the vault and return to login screen"""
        if self.vault_manager.unlocked:
            self.vault_manager.lock()
        
        # Hide main frame
        self.main_frame.pack_forget()
        
        # Show login frame
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        self.password_entry.delete(0, tk.END)
        self.password_entry.focus_set()
        
        self.status_var.set("Vault locked")


def main():
    """Main function to run the GUI"""
    root = tk.Tk()
    app = SimplePasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main() 