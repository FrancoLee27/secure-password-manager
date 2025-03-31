"""
Flask server for cloud synchronization.
This is a simple implementation of a sync server with JWT authentication.
"""

import os
import sys
import json
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity,
    jwt_required, verify_jwt_in_request
)

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.config import DB_DIRECTORY

# Create Flask app
app = Flask(__name__)
CORS(app)

# Configure JWT
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)
jwt = JWTManager(app)

# Setup storage directory
server_data_dir = Path(DB_DIRECTORY) / 'server_data'
if not server_data_dir.exists():
    server_data_dir.mkdir(parents=True, exist_ok=True)

users_file = server_data_dir / 'users.json'
sync_data_dir = server_data_dir / 'sync_data'
if not sync_data_dir.exists():
    sync_data_dir.mkdir(parents=True, exist_ok=True)


def load_users():
    """Load users from file"""
    if not users_file.exists():
        return {}
    
    try:
        with open(users_file, 'r') as f:
            return json.load(f)
    except:
        return {}


def save_users(users):
    """Save users to file"""
    with open(users_file, 'w') as f:
        json.dump(users, f)


def get_user_sync_dir(username):
    """Get the sync directory for a user"""
    user_dir = sync_data_dir / username
    if not user_dir.exists():
        user_dir.mkdir(parents=True, exist_ok=True)
    return user_dir


@app.route('/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    print("Register endpoint called")
    try:
        data = request.get_json()
        print(f"Received data: {data}")
        
        username = data.get('username')
        password_hash = data.get('password_hash')
        
        if not username or not password_hash:
            print("Missing required fields")
            return jsonify({'error': 'Missing required fields'}), 400
        
        users = load_users()
        
        if username in users:
            print(f"Username {username} already exists")
            return jsonify({'error': 'Username already exists'}), 409
        
        # Create new user
        users[username] = {
            'username': username,
            'password_hash': password_hash,
            'created_at': datetime.now().isoformat()
        }
        
        print(f"Created new user: {username}")
        save_users(users)
        
        # Create sync directory
        get_user_sync_dir(username)
        
        # Create and return token
        access_token = create_access_token(identity=username)
        return jsonify({'token': access_token, 'username': username}), 201
    
    except Exception as e:
        print(f"Error in register: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/auth/login', methods=['POST'])
def login():
    """Authenticate a user"""
    print("Login endpoint called")
    try:
        data = request.get_json()
        print(f"Received data: {data}")
        
        username = data.get('username')
        password_hash = data.get('password_hash')
        
        if not username or not password_hash:
            print("Missing required fields")
            return jsonify({'error': 'Missing required fields'}), 400
        
        users = load_users()
        print(f"Loaded users: {list(users.keys())}")
        
        if username not in users:
            print(f"Username {username} not found")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if users[username]['password_hash'] != password_hash:
            print("Password hash doesn't match")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create and return token
        access_token = create_access_token(identity=username)
        print(f"Login successful for {username}")
        return jsonify({'token': access_token, 'username': username}), 200
    
    except Exception as e:
        print(f"Error in login: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/sync/push', methods=['POST'])
@jwt_required()
def push_sync():
    """Push sync data to the server"""
    try:
        # Get current user
        username = get_jwt_identity()
        if not username:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Get sync data
        sync_package = request.get_json()
        
        if not sync_package:
            return jsonify({'error': 'No sync package provided'}), 400
        
        # Required fields
        required_fields = ['encrypted_data', 'iv', 'auth_tag', 'timestamp', 'client_id']
        for field in required_fields:
            if field not in sync_package:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Generate sync ID
        sync_id = str(uuid.uuid4())
        
        # Add metadata
        sync_package['sync_id'] = sync_id
        sync_package['server_timestamp'] = int(time.time())
        sync_package['username'] = username
        
        # Save sync package
        user_dir = get_user_sync_dir(username)
        with open(user_dir / f"{sync_id}.json", 'w') as f:
            json.dump(sync_package, f)
        
        # Return success
        return jsonify({'success': True, 'sync_id': sync_id}), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/sync/pull', methods=['POST'])
@jwt_required()
def pull_sync():
    """Pull sync data from the server"""
    try:
        # Get current user
        username = get_jwt_identity()
        if not username:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Get request data
        data = request.get_json()
        client_id = data.get('client_id')
        last_sync_id = data.get('last_sync_id')
        
        if not client_id:
            return jsonify({'error': 'Missing client ID'}), 400
        
        # Get user sync directory
        user_dir = get_user_sync_dir(username)
        
        # Find the latest sync package
        sync_files = list(user_dir.glob('*.json'))
        if not sync_files:
            return jsonify({'success': True, 'message': 'No sync data available'}), 200
        
        # Sort by modification time (newest first)
        sync_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
        
        # Load the newest sync package
        with open(sync_files[0], 'r') as f:
            latest_sync = json.load(f)
        
        # If this is the same as the last sync ID, no new data
        if last_sync_id == latest_sync.get('sync_id'):
            return jsonify({
                'success': True,
                'message': 'No new data available',
                'sync_id': last_sync_id
            }), 200
        
        # Don't send data to the same client that uploaded it
        if client_id == latest_sync.get('client_id'):
            # Find the next newest that's not from this client
            other_client_syncs = [
                f for f in sync_files
                if os.path.splitext(f.name)[0] != last_sync_id
            ]
            
            if not other_client_syncs:
                return jsonify({
                    'success': True,
                    'message': 'No new data available from other clients',
                    'sync_id': latest_sync.get('sync_id')
                }), 200
            
            # Get the newest sync from another client
            for sync_file in other_client_syncs:
                with open(sync_file, 'r') as f:
                    sync_data = json.load(f)
                
                if sync_data.get('client_id') != client_id:
                    latest_sync = sync_data
                    break
        
        # Return the sync package
        return jsonify({
            'success': True,
            'sync_package': latest_sync,
            'sync_id': latest_sync.get('sync_id')
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/sync/status', methods=['GET'])
@jwt_required()
def sync_status():
    """Get sync status"""
    try:
        # Get current user
        username = get_jwt_identity()
        if not username:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Get user sync directory
        user_dir = get_user_sync_dir(username)
        
        # Count sync packages
        sync_files = list(user_dir.glob('*.json'))
        
        # Get unique client IDs
        client_ids = set()
        latest_sync = None
        latest_timestamp = 0
        
        for sync_file in sync_files:
            try:
                with open(sync_file, 'r') as f:
                    sync_data = json.load(f)
                
                client_ids.add(sync_data.get('client_id'))
                
                timestamp = sync_data.get('server_timestamp', 0)
                if timestamp > latest_timestamp:
                    latest_timestamp = timestamp
                    latest_sync = sync_data
            except:
                continue
        
        # Return status
        return jsonify({
            'success': True,
            'sync_count': len(sync_files),
            'client_count': len(client_ids),
            'latest_sync_id': latest_sync.get('sync_id') if latest_sync else None,
            'latest_timestamp': latest_timestamp if latest_timestamp else None
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # For development only - in production, use a proper WSGI server
    app.run(debug=True, port=5001) 