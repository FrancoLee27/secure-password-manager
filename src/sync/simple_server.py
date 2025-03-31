"""
Simple sync server for testing.
"""

import os
import json
import logging
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('sync_server')

app = Flask(__name__)

# Simple in-memory storage
users = {}
sync_data = {}

@app.route('/')
def index():
    """Root endpoint for health check"""
    logger.info("Health check endpoint called")
    return jsonify({"status": "running", "endpoints": [rule.rule for rule in app.url_map.iter_rules()]})

@app.route('/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    logger.info(f"Register endpoint called with data: {request.get_json()}")
    try:
        data = request.get_json()
        if not data:
            logger.warning("No data provided in registration request")
            return jsonify({'error': 'No data provided'}), 400

        username = data.get('username')
        password_hash = data.get('password_hash')
        
        if not username or not password_hash:
            logger.warning("Missing username or password_hash in registration request")
            return jsonify({'error': 'Missing username or password_hash'}), 400
        
        if username in users:
            logger.warning(f"Username {username} already exists")
            return jsonify({'error': 'User already exists'}), 409
        
        users[username] = {
            'username': username,
            'password_hash': password_hash
        }
        
        logger.info(f"User registered: {username}")
        return jsonify({
            'token': f"test_token_{username}",
            'username': username
        }), 201
    except Exception as e:
        logger.error(f"Error in register: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    """Login a user"""
    print(f"Login endpoint called with data: {request.get_json()}")
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = data.get('username')
        password_hash = data.get('password_hash')
        
        if not username or not password_hash:
            return jsonify({'error': 'Missing username or password_hash'}), 400
        
        if username not in users:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if users[username]['password_hash'] != password_hash:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        print(f"User logged in: {username}")
        return jsonify({
            'token': f"test_token_{username}",
            'username': username
        }), 200
    except Exception as e:
        print(f"Error in login: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/sync/push', methods=['POST'])
def push():
    """Push sync data"""
    print(f"Push endpoint called")
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        username = token.replace('test_token_', '')
        
        if not token or username not in users:
            return jsonify({'error': 'Unauthorized'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        sync_id = f"sync_{len(sync_data) + 1}"
        sync_data[sync_id] = {
            'username': username,
            'data': data
        }
        
        print(f"Data pushed for user {username}, sync_id: {sync_id}")
        return jsonify({
            'success': True,
            'sync_id': sync_id
        }), 200
    except Exception as e:
        print(f"Error in push: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/sync/pull', methods=['POST'])
def pull():
    """Pull sync data"""
    print(f"Pull endpoint called")
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        username = token.replace('test_token_', '')
        
        if not token or username not in users:
            return jsonify({'error': 'Unauthorized'}), 401
        
        data = request.get_json()
        client_id = data.get('client_id')
        last_sync_id = data.get('last_sync_id')
        
        # Find the latest sync for this user
        latest_sync = None
        latest_id = None
        
        for sync_id, sync in sync_data.items():
            if sync['username'] == username and sync_id != last_sync_id:
                latest_sync = sync
                latest_id = sync_id
        
        if not latest_sync:
            return jsonify({
                'success': True,
                'message': 'No new data available'
            }), 200
        
        print(f"Data pulled for user {username}, sync_id: {latest_id}")
        return jsonify({
            'success': True,
            'sync_package': latest_sync['data'],
            'sync_id': latest_id
        }), 200
    except Exception as e:
        print(f"Error in pull: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/sync/status', methods=['GET'])
def status():
    """Get sync status"""
    print(f"Status endpoint called")
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        username = token.replace('test_token_', '')
        
        if not token or username not in users:
            return jsonify({'error': 'Unauthorized'}), 401
        
        user_syncs = []
        for sync_id, sync in sync_data.items():
            if sync['username'] == username:
                user_syncs.append(sync_id)
        
        return jsonify({
            'success': True,
            'sync_count': len(user_syncs),
            'latest_sync_id': user_syncs[-1] if user_syncs else None
        }), 200
    except Exception as e:
        print(f"Error in status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/debug/users', methods=['GET'])
def debug_users():
    """Debug endpoint to show registered users"""
    return jsonify({
        'users': list(users.keys()),
        'user_data': users
    })

if __name__ == "__main__":
    logger.info("Starting simple sync server on http://localhost:5001")
    logger.info(f"Available routes: {[rule.rule for rule in app.url_map.iter_rules()]}")
    app.run(debug=True, port=5001, host='0.0.0.0') 