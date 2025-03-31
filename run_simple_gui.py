#!/usr/bin/env python3
"""
Simple Password Manager GUI - Self-contained for testing
"""

import tkinter as tk
from tkinter import ttk, messagebox

class SimplePasswordManagerGUI:
    """A simple version of the Password Manager GUI for testing"""
    
    def __init__(self, root):
        """Initialize the GUI"""
        self.root = root
        self.root.title("Simple Password Manager")
        self.root.geometry("600x400")
        
        # Create login frame
        self.login_frame = ttk.Frame(self.root, padding=20)
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(
            self.login_frame, 
            text="🔒 Password Manager", 
            font=("Helvetica", 20, "bold")
        )
        title_label.pack(pady=20)
        
        # Password field
        password_label = ttk.Label(self.login_frame, text="Master Password:")
        password_label.pack(anchor=tk.W)
        
        self.password_entry = ttk.Entry(self.login_frame, show="•", width=30)
        self.password_entry.pack(fill=tk.X, pady=5)
        self.password_entry.bind("<Return>", lambda e: self.login())
        
        # Buttons
        btn_frame = ttk.Frame(self.login_frame)
        btn_frame.pack(pady=20)
        
        login_btn = ttk.Button(btn_frame, text="Login", command=self.login)
        login_btn.pack(side=tk.LEFT, padx=5)
        
        # Set focus to password entry
        self.password_entry.focus_set()
    
    def login(self):
        """Handle login"""
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        # For testing, accept any password
        messagebox.showinfo("Success", "Login successful!")
        self.show_main_screen()
    
    def show_main_screen(self):
        """Show the main application screen"""
        # Hide login frame
        self.login_frame.pack_forget()
        
        # Create main frame
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(
            main_frame, 
            text="Password Manager - Main Screen", 
            font=("Helvetica", 16, "bold")
        )
        title_label.pack(pady=10)
        
        # Content
        message = ttk.Label(
            main_frame,
            text="The GUI is working! This is a simplified version for testing.",
            font=("Helvetica", 12)
        )
        message.pack(pady=20)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)
        
        exit_btn = ttk.Button(btn_frame, text="Exit", command=self.root.quit)
        exit_btn.pack(side=tk.LEFT, padx=5)

if __name__ == "__main__":
    # Create Tkinter root window
    root = tk.Tk()
    
    # Create GUI
    app = SimplePasswordManagerGUI(root)
    
    # Start main loop
    root.mainloop() 