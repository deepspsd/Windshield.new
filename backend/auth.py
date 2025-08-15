from fastapi import APIRouter, HTTPException, Form, UploadFile, File, Body
from passlib.hash import bcrypt
import os
import logging
from .models import RegisterRequest, LoginRequest
from .db import get_mysql_connection

logger = logging.getLogger(__name__)

auth_router = APIRouter(prefix="/api", tags=["Authentication"])

@auth_router.post("/register")
async def register_user(request: RegisterRequest):
    try:
        conn = get_mysql_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database connection error")
        
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (request.email,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Hash password
        hashed_pw = bcrypt.hash(request.password)
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (email, password, name) VALUES (%s, %s, %s)",
            (request.email, hashed_pw, request.name)
        )
        conn.commit()
        cursor.close()
        conn.close()
        
        return {"success": True}
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@auth_router.post("/login")
def login_user(request: LoginRequest):
    try:
        conn = get_mysql_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database connection error")
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (request.email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not user or not bcrypt.verify(request.password, user['password']):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        return {"success": True, "name": user.get("name", ""), "email": user["email"]}
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@auth_router.post("/change_password")
def change_password(data: dict = Body(...)):
    email = data.get("email")
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    if not email or not old_password or not new_password:
        raise HTTPException(status_code=400, detail="Missing required fields.")
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    if not user or not bcrypt.verify(old_password, user['password']):
        cursor.close()
        raise HTTPException(status_code=401, detail="Current password is incorrect.")
    hashed_pw = bcrypt.hash(new_password)
    cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
    conn.commit()
    cursor.close()
    return {"success": True}

@auth_router.post("/update_profile")
def update_profile(data: dict = Body(...)):
    email = data.get("email")
    name = data.get("name")
    if not email or not name:
        raise HTTPException(status_code=400, detail="Missing required fields.")
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET name = %s, email = %s WHERE email = %s", (name, email, email))
    conn.commit()
    cursor.close()
    return {"success": True}

@auth_router.post("/notification_preferences")
def notification_preferences(data: dict = Body(...)):
    email = data.get("email")
    email_notifications = data.get("email_notifications", True)
    sms_notifications = data.get("sms_notifications", False)
    
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users SET 
        email_notifications = %s, 
        sms_notifications = %s 
        WHERE email = %s
    """, (email_notifications, sms_notifications, email))
    conn.commit()
    cursor.close()
    return {"success": True}

@auth_router.post("/upload_profile_picture")
def upload_profile_picture(email: str = Form(...), file: UploadFile = File(...)):
    """Upload profile picture for user"""
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    # Validate file type
    if not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    # Create profile pictures directory
    profile_pics_dir = "profile_pics"
    os.makedirs(profile_pics_dir, exist_ok=True)
    
    # Generate filename
    file_extension = os.path.splitext(file.filename)[1]
    filename = f"{email.replace('@', '_at_')}{file_extension}"
    filepath = os.path.join(profile_pics_dir, filename)
    
    # Save file
    try:
        with open(filepath, "wb") as buffer:
            import shutil
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")
    
    # Update database
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET profile_picture = %s WHERE email = %s", (filename, email))
    conn.commit()
    cursor.close()
    
    return {"success": True, "filename": filename, "url": f"/profile_pics/{filename}"}

@auth_router.delete("/remove_profile_picture")
def remove_profile_picture(data: dict = Body(...)):
    """Remove profile picture for user"""
    email = data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    
    # Get current profile picture
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT profile_picture FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    
    if user and user['profile_picture']:
        # Delete file
        filepath = os.path.join("profile_pics", user['profile_picture'])
        if os.path.exists(filepath):
            os.remove(filepath)
        
        # Update database
        cursor.execute("UPDATE users SET profile_picture = NULL WHERE email = %s", (email,))
        conn.commit()
    
    cursor.close()
    return {"success": True}

@auth_router.get("/get_user")
def get_user(email: str):
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT email, name, profile_pic FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@auth_router.get("/profile-info")
async def get_profile_info(email: str):
    """Get user profile information"""
    try:
        logger = logging.getLogger("profile")
        logger.info(f"Getting profile info for user: {email}")
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            
            # Get user profile info
            user_query = "SELECT email, name, profile_picture, created_at, last_login FROM users WHERE email = %s"
            cursor.execute(user_query, (email,))
            user_result = cursor.fetchone()
            
            if user_result:
                cursor.close()
                return {
                    'email': user_result['email'],
                    'name': user_result['name'] or 'User',
                    'profile_picture': user_result['profile_picture'],
                    'created_at': user_result['created_at'].strftime('%B %Y') if user_result['created_at'] else 'Unknown',
                    'last_login': user_result['last_login'].strftime('%B %d, %Y') if user_result['last_login'] else 'Never',
                    'status': 'Active'
                }
            else:
                cursor.close()
                raise HTTPException(status_code=404, detail="User not found")
        
        raise HTTPException(status_code=500, detail="Database connection failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving profile info: {str(e)}")
