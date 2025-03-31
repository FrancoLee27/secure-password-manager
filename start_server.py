#!/usr/bin/env python3
"""
Script to start the sync server with proper configuration
"""

import os
import sys
import socket
import argparse
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('server.log')
    ]
)
logger = logging.getLogger('server_starter')

def is_port_in_use(port):
    """Check if a port is already in use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def find_available_port(start_port, end_port=10000):
    """Find an available port between start_port and end_port"""
    for port in range(start_port, end_port):
        if not is_port_in_use(port):
            return port
    raise RuntimeError(f"No available ports found between {start_port} and {end_port}")

def start_server(server_module, port=None, host='0.0.0.0'):
    """Start the specified server module on the given port"""
    try:
        # Add the project root to Python path
        project_root = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, project_root)
        
        # If no port specified, find an available one
        if port is None:
            port = find_available_port(5001)
        
        logger.info(f"Starting server {server_module} on http://{host}:{port}")
        
        # Import the specified server module
        if server_module == 'simple':
            from src.sync.simple_server import app
        elif server_module == 'sync':
            from src.sync.sync_server import app
        elif server_module == 'test':
            from src.sync.test_server import app
        else:
            raise ValueError(f"Unknown server module: {server_module}")
        
        # Start the server
        app.run(debug=True, port=port, host=host)
    
    except ImportError as e:
        logger.error(f"Failed to import server module: {e}", exc_info=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to start server: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start the sync server')
    parser.add_argument('--server', choices=['simple', 'sync', 'test'], default='simple',
                        help='Server module to run (default: simple)')
    parser.add_argument('--port', type=int, help='Port to run the server on (default: auto-detect)')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    
    args = parser.parse_args()
    
    logger.info(f"Starting {args.server} server with args: {args}")
    start_server(args.server, args.port, args.host) 