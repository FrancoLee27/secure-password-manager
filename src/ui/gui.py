"""
Graphical User Interface for the Secure Password Manager.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import time
from pathlib import Path

# Add the project root to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(parent_dir)
sys.path.insert(0, root_dir)

# Fix the imports to point to the correct modules
from src.password.vault import VaultManager
from src.password.generator import generate_password
from src.password.strength import analyze_password
from src.sync.cloud_sync import CloudSyncService
from src.ui.dialogs import PasswordEntryDialog, SyncConfigDialog, SyncStatusDialog

# Create global instances
vault_manager = VaultManager()
cloud_sync = CloudSyncService()

class PasswordManagerGUI:
    """Main GUI class for the Password Manager"""
    
    def __init__(self, root):
        """Initialize the GUI"""
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        # Set icon if available
        icon_path = Path(__file__).parent / "assets" / "icon.png"
        if icon_path.exists():
            icon = tk.PhotoImage(file=str(icon_path))
            self.root.iconphoto(True, icon)
        
        # Set theme and style
        self.setup_styles()
        
        # Variables
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        # Auto-lock timer
        self.last_activity = time.time()
        self.check_inactivity()
        
        # Create frames
        self.create_login_frame()
        self.create_main_frame()
        
        # Default to showing login frame
        self.show_login_frame()
        
        # Bind events
        self.root.bind("<Button-1>", self.reset_inactivity_timer)
        self.root.bind("<Key>", self.reset_inactivity_timer)
    
    def setup_styles(self):
        """Setup custom styles"""
        style = ttk.Style()
        
        # Configure styles based on platform
        if sys.platform.startswith('win'):
            style.theme_use('vista')
        elif sys.platform.startswith('darwin'):
            style.theme_use('aqua')
        else:
            style.theme_use('clam')
        
        # Custom button style
        style.configure('TButton', padding=6, relief="flat", background="#eeeeee")
        style.map('TButton',
            foreground=[('pressed', 'black'), ('active', 'black')],
            background=[('pressed', '#cccccc'), ('active', '#dddddd')]
        )
        
        # Custom entry style
        style.configure('TEntry', padding=5)
    
    def create_login_frame(self):
        """Create the login frame"""
        self.login_frame = ttk.Frame(self.root, padding=20)
        
        # Logo or title
        title_label = ttk.Label(
            self.login_frame, 
            text="🔒 Secure Password Manager", 
            font=("Helvetica", 20, "bold")
        )
        title_label.pack(pady=20)
        
        subtitle_label = ttk.Label(
            self.login_frame,
            text="A zero-knowledge, secure password management solution",
            font=("Helvetica", 12)
        )
        subtitle_label.pack(pady=10)
        
        # Password field
        password_frame = ttk.Frame(self.login_frame)
        password_frame.pack(pady=30, fill=tk.X)
        
        password_label = ttk.Label(password_frame, text="Master Password:")
        password_label.pack(anchor=tk.W)
        
        self.password_entry = ttk.Entry(password_frame, show="•", width=30)
        self.password_entry.pack(fill=tk.X, pady=5)
        self.password_entry.bind("<Return>", lambda e: self.unlock_vault())
        
        # Buttons
        btn_frame = ttk.Frame(self.login_frame)
        btn_frame.pack(pady=20)
        
        unlock_btn = ttk.Button(btn_frame, text="Unlock Vault", command=self.unlock_vault)
        unlock_btn.pack(side=tk.LEFT, padx=5)
        
        create_btn = ttk.Button(btn_frame, text="Create New Vault", command=self.create_new_vault)
        create_btn.pack(side=tk.LEFT, padx=5)
        
        # Status bar
        status_bar = ttk.Label(self.login_frame, textvariable=self.status_var, font=("Helvetica", 10))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
    
    def create_main_frame(self):
        """Create the main application frame"""
        self.main_frame = ttk.Frame(self.root)
        
        # Create menu bar
        self.create_menu()
        
        # Create toolbar
        toolbar = ttk.Frame(self.main_frame)
        toolbar.pack(side=tk.TOP, fill=tk.X)
        
        # Add search field
        search_label = ttk.Label(toolbar, text="Search:")
        search_label.pack(side=tk.LEFT, padx=5)
        
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind("<KeyRelease>", self.on_search)
        
        # Add buttons
        add_btn = ttk.Button(toolbar, text="Add Entry", command=self.add_entry)
        add_btn.pack(side=tk.LEFT, padx=5)
        
        gen_btn = ttk.Button(toolbar, text="Generate Password", command=self.generate_password)
        gen_btn.pack(side=tk.LEFT, padx=5)
        
        sync_btn = ttk.Button(toolbar, text="Sync Vault", command=self.sync_vault)
        sync_btn.pack(side=tk.LEFT, padx=5)
        
        # Create password list
        list_frame = ttk.Frame(self.main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create Treeview for password list
        columns = ("title", "username", "url", "created", "updated", "strength")
        self.password_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        
        # Define headings
        self.password_tree.heading("title", text="Title")
        self.password_tree.heading("username", text="Username")
        self.password_tree.heading("url", text="URL")
        self.password_tree.heading("created", text="Created")
        self.password_tree.heading("updated", text="Updated")
        self.password_tree.heading("strength", text="Strength")
        
        # Define columns
        self.password_tree.column("title", width=150)
        self.password_tree.column("username", width=150)
        self.password_tree.column("url", width=150)
        self.password_tree.column("created", width=100)
        self.password_tree.column("updated", width=100)
        self.password_tree.column("strength", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.password_tree.yview)
        self.password_tree.configure(yscroll=scrollbar.set)
        
        # Pack elements
        self.password_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind events
        self.password_tree.bind("<Double-1>", self.on_entry_double_click)
        self.password_tree.bind("<Return>", self.on_entry_double_click)
        
        # Create status bar
        status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_menu(self):
        """Create the application menu"""
        menu_bar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Add Entry", command=self.add_entry)
        file_menu.add_command(label="Generate Password", command=self.generate_password)
        file_menu.add_separator()
        file_menu.add_command(label="Lock Vault", command=self.lock_vault)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)
        
        # Edit menu
        edit_menu = tk.Menu(menu_bar, tearoff=0)
        edit_menu.add_command(label="Edit Entry", command=self.edit_selected_entry)
        edit_menu.add_command(label="Delete Entry", command=self.delete_selected_entry)
        menu_bar.add_cascade(label="Edit", menu=edit_menu)
        
        # Sync menu
        sync_menu = tk.Menu(menu_bar, tearoff=0)
        sync_menu.add_command(label="Sync Now", command=self.sync_vault)
        sync_menu.add_command(label="Configure Sync", command=self.configure_sync)
        sync_menu.add_command(label="Sync Status", command=self.view_sync_status)
        menu_bar.add_cascade(label="Sync", menu=sync_menu)
        
        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menu_bar)
    
    def show_login_frame(self):
        """Show the login frame and hide the main frame"""
        self.main_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        self.password_entry.focus_set()
    
    def show_main_frame(self):
        """Show the main frame and hide the login frame"""
        self.login_frame.pack_forget()
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.load_password_entries()
    
    def unlock_vault(self):
        """Unlock the vault with the master password"""
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter your master password")
            return
        
        self.status_var.set("Unlocking vault...")
        self.root.update()
        
        try:
            result = vault_manager.unlock(password)
            if result['success']:
                self.show_main_frame()
                self.status_var.set(f"Vault unlocked. Auto-lock set to {vault_manager.auto_lock_timeout} seconds.")
            else:
                messagebox.showerror("Error", result.get('message', "Failed to unlock vault"))
                self.status_var.set("Ready")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unlock vault: {str(e)}")
            self.status_var.set("Ready")
        
        # Clear password field
        self.password_entry.delete(0, tk.END)
    
    def create_new_vault(self):
        """Create a new vault"""
        password = simpledialog.askstring("Create Vault", "Enter new master password:", show="•")
        if not password:
            return
            
        confirm = simpledialog.askstring("Create Vault", "Confirm master password:", show="•")
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        self.status_var.set("Creating vault...")
        self.root.update()
        
        try:
            result = vault_manager.create_user(password)
            if result['success']:
                messagebox.showinfo("Success", "Vault created successfully!")
                result = vault_manager.unlock(password)
                if result['success']:
                    self.show_main_frame()
                    self.status_var.set(f"Vault unlocked. Auto-lock set to {vault_manager.auto_lock_timeout} seconds.")
                else:
                    self.status_var.set("Ready")
            else:
                messagebox.showerror("Error", result.get('message', "Failed to create vault"))
                self.status_var.set("Ready")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create vault: {str(e)}")
            self.status_var.set("Ready")
    
    def load_password_entries(self):
        """Load password entries from the vault"""
        if not vault_manager.unlocked:
            return
            
        self.status_var.set("Loading entries...")
        self.root.update()
        
        # Clear existing entries
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
            
        try:
            result = vault_manager.get_all_passwords()
            if result['success']:
                entries = result['entries']
                for entry in entries:
                    # Format dates
                    created = entry.get('created_at', '').split('T')[0] if 'created_at' in entry else ''
                    updated = entry.get('updated_at', '').split('T')[0] if 'updated_at' in entry else ''
                    
                    # Get strength label
                    strength = entry.get('strength', {}).get('label', 'N/A')
                    
                    # Add entry to tree
                    self.password_tree.insert(
                        "", tk.END,
                        values=(
                            entry.get('title', ''),
                            entry.get('username', ''),
                            entry.get('url', ''),
                            created,
                            updated,
                            strength
                        ),
                        tags=(entry.get('id', ''),)
                    )
                
                self.status_var.set(f"Loaded {len(entries)} entries")
            else:
                self.status_var.set("Failed to load entries")
                messagebox.showerror("Error", result.get('message', "Failed to load entries"))
        except Exception as e:
            self.status_var.set("Error loading entries")
            messagebox.showerror("Error", f"Failed to load entries: {str(e)}")
    
    def add_entry(self):
        """Add a new password entry"""
        if not vault_manager.unlocked:
            messagebox.showinfo("Info", "Please unlock the vault first")
            return
            
        dialog = PasswordEntryDialog(self.root, vault_manager, title="Add Password Entry")
        
        if dialog.result:
            self.load_password_entries()
            self.status_var.set("Entry added successfully")
    
    def edit_selected_entry(self):
        """Edit the selected password entry"""
        if not vault_manager.unlocked:
            messagebox.showinfo("Info", "Please unlock the vault first")
            return
            
        # Get selected item
        selected = self.password_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select an entry to edit")
            return
        
        # Get entry ID
        entry_id = self.password_tree.item(selected[0], "tags")[0]
        
        # Open edit dialog
        dialog = PasswordEntryDialog(
            self.root, vault_manager, entry_id=entry_id, title="Edit Password Entry"
        )
        
        if dialog.result:
            self.load_password_entries()
            self.status_var.set("Entry updated successfully")
    
    def delete_selected_entry(self):
        """Delete the selected password entry"""
        if not vault_manager.unlocked:
            messagebox.showinfo("Info", "Please unlock the vault first")
            return
            
        # Get selected item
        selected = self.password_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select an entry to delete")
            return
        
        # Get entry ID
        entry_id = self.password_tree.item(selected[0], "tags")[0]
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm", "Are you sure you want to delete this entry?"):
            return
        
        # Delete entry
        result = vault_manager.delete_password(entry_id)
        
        if result['success']:
            self.load_password_entries()
            self.status_var.set("Entry deleted successfully")
        else:
            messagebox.showerror("Error", result.get('message', "Failed to delete entry"))
    
    def on_entry_double_click(self, event):
        """Handle double-click on an entry"""
        self.edit_selected_entry()
    
    def on_search(self, event):
        """Handle search"""
        search_text = self.search_var.get().lower()
        
        if not search_text:
            self.load_password_entries()
            return
            
        # Clear existing entries
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
            
        # Search entries
        result = vault_manager.get_all_passwords()
        if result['success']:
            entries = result['entries']
            found = 0
            
            for entry in entries:
                # Check if search text is in title, username, or URL
                if (search_text in entry.get('title', '').lower() or 
                    search_text in entry.get('username', '').lower() or
                    search_text in entry.get('url', '').lower()):
                    
                    found += 1
                    
                    # Format dates
                    created = entry.get('created_at', '').split('T')[0] if 'created_at' in entry else ''
                    updated = entry.get('updated_at', '').split('T')[0] if 'updated_at' in entry else ''
                    
                    # Get strength label
                    strength = entry.get('strength', {}).get('label', 'N/A')
                    
                    # Add entry to tree
                    self.password_tree.insert(
                        "", tk.END,
                        values=(
                            entry.get('title', ''),
                            entry.get('username', ''),
                            entry.get('url', ''),
                            created,
                            updated,
                            strength
                        ),
                        tags=(entry.get('id', ''),)
                    )
            
            self.status_var.set(f"Found {found} matching entries")
    
    def generate_password(self):
        """Generate a random password"""
        password = generate_password()
        
        # Create popup dialog
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
        
        ttk.Label(frame, text=f"Strength: {strength['label']} ({strength['score']}/100)").pack(pady=5)
        
        # Add buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        
        def copy_to_clipboard():
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard")
        
        copy_btn = ttk.Button(btn_frame, text="Copy to Clipboard", command=copy_to_clipboard)
        copy_btn.pack(side=tk.LEFT, padx=5)
        
        close_btn = ttk.Button(btn_frame, text="Close", command=dialog.destroy)
        close_btn.pack(side=tk.LEFT, padx=5)
    
    def sync_vault(self):
        """Synchronize the vault with the cloud"""
        if not vault_manager.unlocked:
            messagebox.showinfo("Info", "Please unlock the vault first")
            return
        
        status = cloud_sync.get_sync_status()
        if not status['configured']:
            if messagebox.askyesno("Not Configured", 
                                  "Sync is not configured. Would you like to configure it now?"):
                self.configure_sync()
            return
        
        self.status_var.set("Syncing...")
        self.root.update()
        
        # Start sync in a separate thread to avoid freezing the UI
        def sync_thread():
            try:
                # If not authenticated, authenticate first
                if not status['authenticated']:
                    # Get username and password
                    username = simpledialog.askstring("Sync", "Username:")
                    if not username:
                        self.status_var.set("Sync cancelled")
                        return
                        
                    password = simpledialog.askstring("Sync", "Password:", show="•")
                    if not password:
                        self.status_var.set("Sync cancelled")
                        return
                    
                    # Authenticate
                    auth_result = cloud_sync.authenticate(username, password)
                    if not auth_result['success']:
                        self.status_var.set("Authentication failed")
                        messagebox.showerror("Error", 
                                            auth_result.get('message', "Authentication failed"))
                        return
                
                # Get vault data
                vault_result = vault_manager.get_all_passwords()
                if not vault_result['success']:
                    self.status_var.set("Failed to get vault data")
                    messagebox.showerror("Error", 
                                       vault_result.get('message', "Failed to get vault data"))
                    return
                
                # Push changes
                self.status_var.set("Pushing changes...")
                push_result = cloud_sync.push_vault(vault_manager.vault_key, vault_result['entries'])
                
                if not push_result['success']:
                    self.status_var.set("Push failed")
                    messagebox.showerror("Error", 
                                       push_result.get('message', "Failed to push changes"))
                    return
                
                # Pull changes
                self.status_var.set("Pulling changes...")
                pull_result = cloud_sync.pull_vault(vault_manager.vault_key)
                
                if not pull_result['success']:
                    self.status_var.set("Pull failed")
                    messagebox.showerror("Error", 
                                       pull_result.get('message', "Failed to pull changes"))
                    return
                
                # If data was pulled, update vault
                if pull_result.get('data'):
                    # Merge data
                    merged_data = cloud_sync.resolve_conflicts(
                        vault_result['entries'], pull_result['data']
                    )
                    
                    # Update each entry in the vault
                    for entry in merged_data:
                        vault_manager.update_password(entry, save=False)
                    
                    # Save vault
                    vault_manager.save_vault()
                    
                    # Reload entries
                    self.load_password_entries()
                    
                    self.status_var.set(f"Synchronized {len(merged_data)} entries")
                else:
                    self.status_var.set("Sync completed, no changes to pull")
            except Exception as e:
                self.status_var.set("Sync error")
                messagebox.showerror("Error", f"Sync error: {str(e)}")
        
        # Start the thread
        threading.Thread(target=sync_thread).start()
    
    def configure_sync(self):
        """Configure cloud synchronization"""
        dialog = SyncConfigDialog(self.root, cloud_sync)
        
        if dialog.result:
            self.status_var.set(f"Sync configured with {dialog.result}")
    
    def view_sync_status(self):
        """View cloud synchronization status"""
        SyncStatusDialog(self.root, cloud_sync)
    
    def lock_vault(self):
        """Lock the vault"""
        if vault_manager.unlocked:
            vault_manager.lock()
            self.show_login_frame()
            self.status_var.set("Vault locked")
    
    def reset_inactivity_timer(self, event=None):
        """Reset the inactivity timer"""
        self.last_activity = time.time()
    
    def check_inactivity(self):
        """Check for inactivity and lock vault if needed"""
        if vault_manager.unlocked and time.time() - self.last_activity > vault_manager.auto_lock_timeout:
            self.lock_vault()
            messagebox.showinfo("Auto-Lock", "Vault has been locked due to inactivity")
        
        # Schedule next check
        self.root.after(5000, self.check_inactivity)
    
    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo(
            "About Secure Password Manager",
            "Secure Password Manager\n\n"
            "A zero-knowledge, secure password management solution featuring "
            "strong encryption, breach checking, and password strength analysis."
        )


def main():
    """Main entry point for the GUI"""
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main() 