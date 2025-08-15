from fastapi import FastAPI, HTTPException, BackgroundTasks, Form, UploadFile, File, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
import mysql.connector
from mysql.connector import Error
from pydantic import BaseModel
from datetime import datetime
from dotenv import load_dotenv
import os
import asyncio
import aiohttp
import re
import urllib.parse
import hashlib
import json
import base64
from typing import Optional, Dict, Any

import logging
import time
from uuid import uuid4
from passlib.hash import bcrypt
from jinja2 import Template

from fastapi.middleware.gzip import GZipMiddleware
from threading import Thread
from .db import create_database_and_tables
from .routes import register_routes
# Import ML modules with lazy loading
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'ml_models'))
from ml_integration import get_ml_engine, integrate_ml_with_scan, initialize_ml_engine_async

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WebShield API", description="Real-time Fake Website & Malware Detection", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

# Startup event to initialize services in background
@app.on_event("startup")
async def startup_event():
    """Initialize services in background on startup"""
    start_time = time.time()
    logger.info("Starting WebShield server...")
    
    # Start all initializations in parallel without blocking
    import threading
    
    def init_ml():
        try:
            initialize_ml_engine_async()
            logger.info("ML engine initialization started in background")
        except Exception as e:
            logger.warning(f"ML engine initialization failed: {e}")
    
    def init_db():
        try:
            create_database_and_tables()
            logger.info("Database initialization completed in background")
        except Exception as e:
            logger.warning(f"Database initialization failed: {e}")
    
    # Start both threads immediately without waiting
    threading.Thread(target=init_ml, daemon=True).start()
    threading.Thread(target=init_db, daemon=True).start()
    
    startup_time = time.time() - start_time
    logger.info(f"Server startup completed in {startup_time:.2f}s (services initializing in background)")

# Import and register all routes
register_routes(app)

def find_available_port(start_port=8000, max_attempts=100):
    """Find an available port starting from start_port"""
    import socket
    
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
    import subprocess
    import platform
    
    try:
        if platform.system() == "Windows":
            # Find process using the port
            result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if f':{port}' in line and 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        pid = parts[-1]
                        # Kill the process
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
                    subprocess.run(['kill', '-9', pid], 
                                 capture_output=True, check=False)
                return True
    except Exception as e:
        print(f"Warning: Could not kill process on port {port}: {e}")
    return False

if __name__ == "__main__":
    import uvicorn
    import logging
    import socket
    import sys
    
    logger = logging.getLogger("server")
    logger.info("Starting server...")

    # Find available port
    preferred_port = 8000
    try:
        available_port = find_available_port(preferred_port)
        if available_port != preferred_port:
            logger.info(f"Port {preferred_port} is busy, using port {available_port}")
        else:
            logger.info(f"Using preferred port {preferred_port}")
    except RuntimeError as e:
        logger.error(f"Port allocation failed: {e}")
        sys.exit(1)

    logger.info(f"Starting uvicorn server on port {available_port}...")
    try:
        uvicorn.run(
            app, 
            host="127.0.0.1", 
            port=available_port,
            workers=1,
            access_log=False,
            log_level="warning",
            loop="asyncio",
            reload=False
        )
    except OSError as e:
        if "Address already in use" in str(e) or "10048" in str(e):
            logger.warning(f"Port {available_port} became busy, attempting to kill existing process...")
            if kill_process_on_port(available_port):
                logger.info("Killed existing process, retrying...")
                uvicorn.run(
                    app, 
                    host="127.0.0.1", 
                    port=available_port,
                    workers=1,
                    access_log=False,
                    log_level="warning",
                    loop="asyncio",
                    reload=False
                )
            else:
                logger.error(f"Could not free port {available_port}, trying next available port...")
                available_port = find_available_port(available_port + 1)
                logger.info(f"Retrying on port {available_port}")
                uvicorn.run(
                    app, 
                    host="127.0.0.1", 
                    port=available_port,
                    workers=1,
                    access_log=False,
                    log_level="warning",
                    loop="asyncio",
                    reload=False
                )
        else:
            raise