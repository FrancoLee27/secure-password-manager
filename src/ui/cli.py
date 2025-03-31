"""
Command-line interface for the password manager.
"""

import sys
import os
import getpass
import argparse
import json
import time
from datetime import datetime
import signal
import re

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.password.vault import vault_manager
from src.password.strength import strength_analyzer
from src.password.breach_checker import breach_checker
from src.sync.cloud_sync import cloud_sync_service


def signal_handler(sig, frame):
    """Handle Ctrl+C"""
    print("\nSafely shutting down...")
    vault_manager.lock()
    sys.exit(0)


# Set up signal handler for clean exit
signal.signal(signal.SIGINT, signal_handler)


class PasswordManagerCLI:
    """Command-line interface for interacting with the password manager"""
    
    def __init__(self):
        """Initialize the CLI"""
        self.parser = self._create_parser()
        
        # Add cloud sync service
        self.cloud_sync = cloud_sync_service
        
        # Register additional command handlers
        self.command_handlers = {
            'config-sync': self.handle_config_sync,
            'sync': self.handle_sync,
            'sync-status': self.handle_sync_status,
        }
    
    def _create_parser(self):
        """Create the argument parser for the CLI"""
        parser = argparse.ArgumentParser(
            description='Secure Password Manager',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  python cli.py create-user
  python cli.py unlock
  python cli.py add
  python cli.py list
  python cli.py get 5f3a7b2e-9c8d-4a6b-b1e2-3f4a5c6d7e8f
  python cli.py generate
  python cli.py analyze "MyP@ssw0rd"
  python cli.py check "MyP@ssw0rd"
  python cli.py lock
  python cli.py config-sync --url http://localhost:5001
  python cli.py sync
  python cli.py sync-status
''')
        
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        
        # Create user command
        create_user_parser = subparsers.add_parser('create-user', help='Create a new user')
        create_user_parser.add_argument('--username', help='Username (prompt if not provided)')
        
        # Unlock command
        unlock_parser = subparsers.add_parser('unlock', help='Unlock the vault')
        unlock_parser.add_argument('--timeout', type=int, default=300, 
                                help='Auto-lock timeout in seconds (default: 300)')
        
        # Lock command
        subparsers.add_parser('lock', help='Lock the vault')
        
        # Add password command
        subparsers.add_parser('add', help='Add a password entry')
        
        # List passwords command
        list_parser = subparsers.add_parser('list', help='List all password entries')
        list_parser.add_argument('--show-passwords', action='store_true', 
                               help='Show actual passwords in the list')
        
        # Get password command
        get_parser = subparsers.add_parser('get', help='Get a password entry')
        get_parser.add_argument('id', help='Entry ID')
        
        # Update password command
        update_parser = subparsers.add_parser('update', help='Update a password entry')
        update_parser.add_argument('id', help='Entry ID')
        
        # Delete password command
        delete_parser = subparsers.add_parser('delete', help='Delete a password entry')
        delete_parser.add_argument('id', help='Entry ID')
        
        # Generate password command
        generate_parser = subparsers.add_parser('generate', help='Generate a secure password')
        generate_parser.add_argument('--length', type=int, default=16, help='Password length')
        generate_parser.add_argument('--no-uppercase', action='store_true', help='Exclude uppercase letters')
        generate_parser.add_argument('--no-lowercase', action='store_true', help='Exclude lowercase letters')
        generate_parser.add_argument('--no-numbers', action='store_true', help='Exclude numbers')
        generate_parser.add_argument('--no-symbols', action='store_true', help='Exclude symbols')
        generate_parser.add_argument('--passphrase', action='store_true', help='Generate a passphrase instead')
        generate_parser.add_argument('--words', type=int, default=5, help='Number of words in passphrase')
        
        # Analyze password command
        analyze_parser = subparsers.add_parser('analyze', help='Analyze password strength')
        analyze_parser.add_argument('password', help='Password to analyze')
        
        # Check for breaches command
        check_parser = subparsers.add_parser('check', help='Check if password has been compromised')
        check_parser.add_argument('password', help='Password to check')
        
        # Cloud sync commands
        config_sync_parser = subparsers.add_parser('config-sync', help='Configure cloud synchronization')
        config_sync_parser.add_argument('--url', required=True, help='Sync server URL')
        
        sync_parser = subparsers.add_parser('sync', help='Synchronize the vault with the cloud')
        sync_parser.add_argument('--pull-only', action='store_true', help='Only pull changes from the server')
        sync_parser.add_argument('--push-only', action='store_true', help='Only push changes to the server')
        
        subparsers.add_parser('sync-status', help='Show cloud synchronization status')
        
        return parser
    
    def run(self, args=None):
        """Run the CLI with the given arguments"""
        args = self.parser.parse_args(args)
        
        if not args.command:
            self.parser.print_help()
            return
        
        # Check for sync commands first
        if args.command in self.command_handlers:
            # Convert args Namespace to a list for the handler
            handler_args = []
            for arg_name, arg_value in vars(args).items():
                if arg_name != 'command' and arg_value is not None:
                    if isinstance(arg_value, bool) and arg_value:
                        handler_args.append(f"--{arg_name}")
                    elif not isinstance(arg_value, bool):
                        handler_args.append(f"--{arg_name}")
                        handler_args.append(str(arg_value))
            
            self.command_handlers[args.command](handler_args)
            return
        
        # Call the appropriate method for other commands
        method_name = f'_cmd_{args.command.replace("-", "_")}'
        method = getattr(self, method_name, None)
        
        if method:
            method(args)
        else:
            print(f"Unknown command: {args.command}")
            self.parser.print_help()
    
    def _cmd_create_user(self, args):
        """Create a new user command"""
        username = args.username
        if not username:
            username = input("Enter username: ")
        
        master_password = getpass.getpass("Create master password: ")
        confirm_password = getpass.getpass("Confirm master password: ")
        
        if master_password != confirm_password:
            print("Passwords do not match.")
            return
        
        # Analyze password strength
        strength_result = strength_analyzer.analyze_password(master_password)
        if strength_result['score'] < 50:
            print(f"Warning: Master password strength is {strength_result['strength']} ({strength_result['score']}/100)")
            print("Consider using a stronger password.")
            print("Suggestions:")
            for feedback in strength_result['feedback']:
                print(f"- {feedback}")
            
            proceed = input("Proceed with this password anyway? (y/n): ")
            if proceed.lower() != 'y':
                return
        
        # Check for breaches
        breach_result = breach_checker.check_password(master_password)
        if breach_result['compromised']:
            print(f"WARNING: {breach_result['message']}")
            proceed = input("This password has been compromised. Proceed anyway? (y/n): ")
            if proceed.lower() != 'y':
                return
        
        # Create user
        result = vault_manager.create_user(username, master_password)
        if result['success']:
            print(result['message'])
            print(f"User '{username}' created and vault unlocked.")
        else:
            print(f"Error: {result['message']}")
    
    def _cmd_unlock(self, args):
        """Unlock the vault command"""
        master_password = getpass.getpass("Enter master password: ")
        
        result = vault_manager.unlock(master_password, auto_lock_seconds=args.timeout)
        if result['success']:
            print(result['message'])
            print(f"Auto-lock set to {args.timeout} seconds.")
        else:
            print(f"Error: {result['message']}")
    
    def _cmd_lock(self, args):
        """Lock the vault command"""
        result = vault_manager.lock()
        if result['success']:
            print(result['message'])
        else:
            print(f"Error: {result['message']}")
    
    def _cmd_add(self, args):
        """Add a password entry command"""
        title = input("Title: ")
        username = input("Username: ")
        password = getpass.getpass("Password (leave empty to generate): ")
        
        if not password:
            # Generate a password
            print("Generating a secure password...")
            gen_result = vault_manager.generate_password()
            if gen_result['success']:
                password = gen_result['password']
                print(f"Generated password: {password}")
                print(f"Strength: {gen_result['strength']['level']} ({gen_result['strength']['score']}/100)")
                if gen_result['breach']['compromised']:
                    print(f"Warning: {gen_result['breach']['message']}")
            else:
                print(f"Error: {gen_result['message']}")
                return
        
        # Optional fields
        url = input("URL (optional): ")
        notes = input("Notes (optional): ")
        
        # Create entry
        entry = {
            'title': title,
            'username': username,
            'password': password
        }
        
        if url:
            entry['url'] = url
        if notes:
            entry['notes'] = notes
        
        # Add to vault
        result = vault_manager.add_password(entry)
        if result['success']:
            print(f"Entry added with ID: {result['entry_id']}")
        else:
            print(f"Error: {result['message']}")
    
    def _cmd_list(self, args):
        """List all password entries command"""
        result = vault_manager.get_all_passwords()
        if not result['success']:
            print(f"Error: {result['message']}")
            return
        
        entries = result['entries']
        if not entries:
            print("No entries found in the vault.")
            return
        
        # Print table header
        headers = ["ID", "Title", "Username", "URL", "Created", "Updated", "Strength"]
        if args.show_passwords:
            headers.insert(3, "Password")
        
        # Format as table
        print("\nPassword Vault Entries:")
        print("-" * 100)
        print(" | ".join(h.ljust(15) for h in headers))
        print("-" * 100)
        
        for entry in entries:
            row = [
                entry.get('id', '')[:8] + "...",  # Truncate ID
                entry.get('title', ''),
                entry.get('username', ''),
            ]
            
            if args.show_passwords:
                row.append(entry.get('password', ''))
            
            row.extend([
                entry.get('url', ''),
                self._format_date(entry.get('created_at', '')),
                self._format_date(entry.get('updated_at', '')),
                f"{entry.get('strength', {}).get('level', 'N/A')} ({entry.get('strength', {}).get('score', 0)}/100)"
            ])
            
            print(" | ".join(str(field).ljust(15) for field in row))
        
        print("-" * 100)
        print(f"Total entries: {len(entries)}")
    
    def _cmd_get(self, args):
        """Get a password entry command"""
        result = vault_manager.get_password(args.id)
        if not result['success']:
            print(f"Error: {result['message']}")
            return
        
        entry = result['entry']
        
        # Print entry details
        print("\nPassword Entry Details:")
        print("-" * 60)
        print(f"ID:       {entry.get('id', '')}")
        print(f"Title:    {entry.get('title', '')}")
        print(f"Username: {entry.get('username', '')}")
        print(f"Password: {entry.get('password', '')}")
        
        if 'url' in entry:
            print(f"URL:      {entry['url']}")
        
        if 'notes' in entry:
            print(f"Notes:    {entry['notes']}")
        
        print(f"Created:  {self._format_date(entry.get('created_at', ''))}")
        print(f"Updated:  {self._format_date(entry.get('updated_at', ''))}")
        
        # Print strength and breach information
        if 'strength' in entry:
            print("\nPassword Strength:")
            print(f"Score:    {entry['strength'].get('score', 0)}/100 ({entry['strength'].get('level', 'N/A')})")
            print("Feedback: ")
            for feedback in entry['strength'].get('feedback', []):
                print(f"- {feedback}")
        
        if 'breach' in entry:
            print("\nBreach Check:")
            print(breach_checker.generate_breach_notification(entry['breach']))
    
    def _cmd_update(self, args):
        """Update a password entry command"""
        # First get the existing entry
        get_result = vault_manager.get_password(args.id)
        if not get_result['success']:
            print(f"Error: {get_result['message']}")
            return
        
        entry = get_result['entry']
        
        # Show current values and prompt for new ones
        print(f"\nUpdating entry: {entry.get('title', '')}")
        print("Leave fields empty to keep current values.")
        
        title = input(f"Title [{entry.get('title', '')}]: ")
        username = input(f"Username [{entry.get('username', '')}]: ")
        
        password_options = input(f"Password [keep current/generate/enter new] (k/g/n): ")
        password = None
        
        if password_options.lower() == 'g':
            # Generate a password
            print("Generating a secure password...")
            gen_result = vault_manager.generate_password()
            if gen_result['success']:
                password = gen_result['password']
                print(f"Generated password: {password}")
                print(f"Strength: {gen_result['strength']['level']} ({gen_result['strength']['score']}/100)")
                if gen_result['breach']['compromised']:
                    print(f"Warning: {gen_result['breach']['message']}")
            else:
                print(f"Error: {gen_result['message']}")
                return
        elif password_options.lower() == 'n':
            password = getpass.getpass("New password: ")
        
        url = input(f"URL [{entry.get('url', '')}]: ")
        notes = input(f"Notes [{entry.get('notes', '')}]: ")
        
        # Create updates dictionary with only changed fields
        updates = {}
        if title:
            updates['title'] = title
        if username:
            updates['username'] = username
        if password:
            updates['password'] = password
        if url:
            updates['url'] = url
        if notes:
            updates['notes'] = notes
        
        if not updates:
            print("No changes made.")
            return
        
        # Update entry
        result = vault_manager.update_password(args.id, updates)
        if result['success']:
            print(f"Entry {args.id} updated successfully.")
        else:
            print(f"Error: {result['message']}")
    
    def _cmd_delete(self, args):
        """Delete a password entry command"""
        # First get the entry to confirm deletion
        get_result = vault_manager.get_password(args.id)
        if not get_result['success']:
            print(f"Error: {get_result['message']}")
            return
        
        entry = get_result['entry']
        
        # Confirm deletion
        confirm = input(f"Are you sure you want to delete '{entry.get('title', '')}' (y/n)? ")
        if confirm.lower() != 'y':
            print("Deletion cancelled.")
            return
        
        # Delete entry
        result = vault_manager.delete_password(args.id)
        if result['success']:
            print(f"Entry {args.id} deleted successfully.")
        else:
            print(f"Error: {result['message']}")
    
    def _cmd_generate(self, args):
        """Generate a secure password command"""
        if args.passphrase:
            # Generate passphrase
            options = {
                'word_count': args.words,
                'capitalize': True,
                'include_number': True,
                'include_symbol': True
            }
            
            result = vault_manager.generate_passphrase(options)
            if result['success']:
                print(f"\nGenerated Passphrase:")
                print("-" * 40)
                print(result['passphrase'])
                print(f"\nStrength: {result['strength']['level']} ({result['strength']['score']}/100)")
                print("\nBreach Check:")
                print(breach_checker.generate_breach_notification(result['breach']))
            else:
                print(f"Error: {result['message']}")
        else:
            # Generate password
            options = {
                'length': args.length,
                'include_uppercase': not args.no_uppercase,
                'include_lowercase': not args.no_lowercase,
                'include_numbers': not args.no_numbers,
                'include_symbols': not args.no_symbols
            }
            
            result = vault_manager.generate_password(options)
            if result['success']:
                print(f"\nGenerated Password:")
                print("-" * 40)
                print(result['password'])
                print(f"\nStrength: {result['strength']['level']} ({result['strength']['score']}/100)")
                print("\nBreach Check:")
                print(breach_checker.generate_breach_notification(result['breach']))
            else:
                print(f"Error: {result['message']}")
    
    def _cmd_analyze(self, args):
        """Analyze password strength command"""
        result = strength_analyzer.analyze_password(args.password)
        
        print(f"\nPassword Strength Analysis:")
        print("-" * 40)
        print(f"Strength: {result['strength']} ({result['score']}/100)")
        print(f"Entropy:  {result['entropy']} bits")
        
        if result['patterns']:
            print("\nDetected patterns:")
            for pattern in result['patterns']:
                print(f"- {pattern}")
        
        print("\nFeedback:")
        for feedback in result['feedback']:
            print(f"- {feedback}")
    
    def _cmd_check(self, args):
        """Check if password has been compromised command"""
        result = breach_checker.check_password(args.password)
        
        print(f"\nPassword Breach Check:")
        print("-" * 40)
        print(breach_checker.generate_breach_notification(result))
    
    def _format_date(self, iso_date_str):
        """Format ISO date string to readable format"""
        if not iso_date_str:
            return "N/A"
        
        try:
            dt = datetime.fromisoformat(iso_date_str)
            return dt.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            return iso_date_str
    
    def handle_config_sync(self, args):
        """
        Configure cloud synchronization
        
        Args:
            args (list): Command arguments
                --url: The sync server URL
        """
        parser = argparse.ArgumentParser(description='Configure cloud synchronization')
        parser.add_argument('--url', required=True, help='Sync server URL')
        parsed_args = parser.parse_args(args)
        
        # Configure sync
        result = self.cloud_sync.configure_sync(parsed_args.url)
        
        if result:
            print("Sync configured successfully")
            print(f"Server URL: {parsed_args.url}")
        else:
            print("Failed to configure sync")
    
    def handle_sync(self, args):
        """
        Synchronize the vault with the cloud
        
        Args:
            args (list): Command arguments
                --pull-only: Only pull changes from the server
                --push-only: Only push changes to the server
        """
        if not vault_manager.unlocked:
            print("Vault is locked. Please unlock it first.")
            return
        
        parser = argparse.ArgumentParser(description='Synchronize vault with cloud')
        parser.add_argument('--pull-only', action='store_true', help='Only pull changes')
        parser.add_argument('--push-only', action='store_true', help='Only push changes')
        parsed_args = parser.parse_args(args)
        
        # Check sync status
        status = self.cloud_sync.get_sync_status()
        if not status['configured']:
            print("Sync is not configured. Use 'config-sync' command first.")
            return
        
        if not status['authenticated']:
            # Authenticate with the sync server
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            
            result = self.cloud_sync.authenticate(username, password)
            if not result['success']:
                print(f"Authentication failed: {result.get('message', 'Unknown error')}")
                return
            
            print("Authentication successful")
        
        # Get vault data from the vault manager
        result = vault_manager.get_all_passwords()
        if not result['success']:
            print(f"Error getting passwords: {result.get('message', 'Unknown error')}")
            return
        
        vault_data = result['entries']
        
        # Perform sync operations
        if not parsed_args.pull_only:
            # Push changes to server
            print("Pushing changes to server...")
            push_result = self.cloud_sync.push_vault(vault_manager.vault_key, vault_data)
            
            if push_result['success']:
                print("Push successful")
            else:
                print(f"Push failed: {push_result.get('message', 'Unknown error')}")
        
        if not parsed_args.push_only:
            # Pull changes from server
            print("Pulling changes from server...")
            pull_result = self.cloud_sync.pull_vault(vault_manager.vault_key)
            
            if pull_result['success']:
                if pull_result.get('data'):
                    print("Received changes from server")
                    
                    # Merge changes
                    merged_data = self.cloud_sync.resolve_conflicts(
                        vault_data, pull_result['data']
                    )
                    
                    # Update local vault
                    # This is simplified - in a real implementation, you'd need to
                    # properly update the vault with the merged data
                    print("Updating local vault with merged changes")
                    
                    # Print summary
                    print(f"Synchronized {len(merged_data)} entries")
                else:
                    print("No changes to pull")
            else:
                print(f"Pull failed: {pull_result.get('message', 'Unknown error')}")
    
    def handle_sync_status(self, args):
        """
        Show cloud synchronization status
        
        Args:
            args (list): Command arguments (unused)
        """
        status = self.cloud_sync.get_sync_status()
        
        print("Cloud Sync Status:")
        print(f"Configured: {'Yes' if status['configured'] else 'No'}")
        print(f"Authenticated: {'Yes' if status['authenticated'] else 'No'}")
        
        if status['last_push']:
            print(f"Last Push: {status['last_push']}")
        
        if status['last_pull']:
            print(f"Last Pull: {status['last_pull']}")
        
        if status['client_id']:
            print(f"Client ID: {status['client_id']}")


def main():
    """Main entry point for the CLI"""
    try:
        cli = PasswordManagerCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
    finally:
        # Ensure the vault is locked when exiting
        try:
            vault_manager.close()
        except:
            pass


if __name__ == "__main__":
    main() 