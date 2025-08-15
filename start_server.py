#!/usr/bin/env python3
"""
Robust server startup script that handles port conflicts automatically.
This script will ensure your server starts successfully every time.
"""

import subprocess
import sys
import time
import socket
import platform
import os

def find_available_port(start_port=8000, max_attempts=100):
    """Find an available port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"No available ports found in range {start_port}-{start_port + max_attempts - 1}")

def kill_process_on_port(port):
    """Kill any process using the specified port"""
    try:
        if platform.system() == "Windows":
            # Find process using the port
            result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if f':{port}' in line and 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        pid = parts[-1]
                        print(f"Killing process {pid} on port {port}")
                        subprocess.run(['taskkill', '/PID', pid, '/F'], 
                                     capture_output=True, check=False)
                        return True
        else:
            # For Unix-like systems
            result = subprocess.run(['lsof', '-ti', f':{port}'], 
                                 capture_output=True, text=True)
            if result.stdout.strip():
                pids = result.stdout.strip().split('\n')
                for pid in pids:
                    print(f"Killing process {pid} on port {port}")
                    subprocess.run(['kill', '-9', pid], 
                                 capture_output=True, check=False)
                return True
    except Exception as e:
        print(f"Warning: Could not kill process on port {port}: {e}")
    return False

def check_port_in_use(port):
    """Check if a port is in use"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', port))
            return False
    except OSError:
        return True

def start_server():
    """Start the server with automatic port handling"""
    start_time = time.time()
    print("🚀 Starting WebShield Server...")
    
    # Check if we're in the right directory
    if not os.path.exists('backend/server.py'):
        print("❌ Error: backend/server.py not found. Please run this script from the project root.")
        sys.exit(1)
    
    # Find available port - optimized for speed
    preferred_port = 8000
    print(f"🔍 Checking port availability...")
    
    # Quick port check with timeout
    if check_port_in_use(preferred_port):
        print(f"⚠️  Port {preferred_port} is busy, attempting to free it...")
        if kill_process_on_port(preferred_port):
            print(f"✅ Freed port {preferred_port}")
            time.sleep(0.5)  # Reduced wait time
        else:
            print(f"⚠️  Could not free port {preferred_port}, finding alternative...")
            try:
                preferred_port = find_available_port(preferred_port + 1, max_attempts=10)  # Reduced max attempts
                print(f"✅ Found available port: {preferred_port}")
            except RuntimeError as e:
                print(f"❌ {e}")
                sys.exit(1)
    else:
        print(f"✅ Port {preferred_port} is available")
    
    # Start the server
    print(f"🎯 Starting server on port {preferred_port}...")
    
    try:
        # Use uvicorn to start the server
        cmd = [
            sys.executable, '-m', 'uvicorn', 
            'backend.server:app',
            '--host', '0.0.0.0',
            '--port', str(preferred_port),
            '--reload'  # Enable auto-reload for development
        ]
        
        print(f"📡 Server will be available at: http://localhost:{preferred_port}")
        print(f"🌐 Network access: http://192.168.29.184:{preferred_port}")
        print("⏹️  Press Ctrl+C to stop the server")
        print("-" * 50)
        
        # Start the server
        subprocess.run(cmd, check=True)
        
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except subprocess.CalledProcessError as e:
        print(f"❌ Server failed to start: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)
    
    # Show startup time if we get here
    startup_time = time.time() - start_time
    print(f"⏱️  Total startup time: {startup_time:.2f}s")

if __name__ == "__main__":
    start_server() 