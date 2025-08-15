from fastapi import APIRouter, HTTPException, BackgroundTasks, Body
from fastapi.responses import HTMLResponse
import hashlib
import json
import logging
from datetime import datetime
from .models import ReportRequest, ApiKeyRequest, ApiSettingsRequest, ExportRequest, DownloadReportRequest
from .db import get_mysql_connection

logger = logging.getLogger(__name__)

api_router = APIRouter(prefix="/api", tags=["API"])

@api_router.get("/migrate-database")
async def migrate_database():
    """Manually run database migration"""
    try:
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor()
            
            # Add user_email column to existing scans table if it doesn't exist
            try:
                cursor.execute("ALTER TABLE scans ADD COLUMN user_email VARCHAR(255)")
                conn.commit()
                logger.info("Successfully added user_email column to scans table")
                return {"success": True, "message": "Added user_email column"}
            except Exception as e:
                if "Duplicate column name" in str(e):
                    logger.info("user_email column already exists in scans table")
                    return {"success": True, "message": "user_email column already exists"}
                else:
                    logger.error(f"Error adding user_email column: {e}")
                    return {"success": False, "error": str(e)}
            finally:
                cursor.close()
        else:
            return {"success": False, "error": "Database connection failed"}
    except Exception as e:
        return {"success": False, "error": str(e)}

@api_router.get("/debug/scan/{scan_id}")
async def debug_scan_result(scan_id: str):
    """Debug endpoint to check scan status"""
    try:
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            
            # First, let's check what database we're connected to
            cursor.execute("SELECT DATABASE() as current_db")
            db_info = cursor.fetchone()
            
            # Check if scan exists
            cursor.execute("SELECT * FROM scans WHERE scan_id = %s", (scan_id,))
            scan = cursor.fetchone()
            
            # Get total scan count
            cursor.execute("SELECT COUNT(*) as total_scans FROM scans")
            total_scans = cursor.fetchone()
            
            cursor.close()
            
            return {
                "scan_id": scan_id,
                "database": db_info['current_db'] if db_info else "unknown",
                "scan_found": scan is not None,
                "scan_data": scan,
                "total_scans_in_db": total_scans['total_scans'] if total_scans else 0,
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {"error": "Database connection failed"}
    except Exception as e:
        return {"error": str(e)}

@api_router.post("/report_blacklist")
def report_blacklist(request: ReportRequest):
    logger = logging.getLogger("report")
    logger.info("Reporting URL as malicious (blacklist): %s", request.url)
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    scan_id = hashlib.md5(f"{request.url}{datetime.now().isoformat()}".encode()).hexdigest()
    cursor = conn.cursor()
    insert_query = """
    INSERT INTO scans (scan_id, url, status, is_malicious, threat_level, malicious_count, suspicious_count, total_engines, ssl_valid, domain_reputation, detection_details, created_at, completed_at, scan_timestamp)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    detection_details = json.dumps({"reason": request.reason or "User reported blacklist"})
    now = datetime.now()
    cursor.execute(insert_query, (
        scan_id, request.url, 'completed', True, 'high', 1, 0, 0, False, 'malicious', detection_details, now, now, now
    ))
    conn.commit()
    cursor.close()
    return {"success": True, "message": "URL reported as malicious (blacklist)."}

@api_router.post("/report_whitelist")
def report_whitelist(request: ReportRequest):
    logger = logging.getLogger("report")
    logger.info("Reporting URL as clean (whitelist): %s", request.url)
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    scan_id = hashlib.md5(f"{request.url}{datetime.now().isoformat()}".encode()).hexdigest()
    cursor = conn.cursor()
    insert_query = """
    INSERT INTO scans (scan_id, url, status, is_malicious, threat_level, malicious_count, suspicious_count, total_engines, ssl_valid, domain_reputation, detection_details, created_at, completed_at, scan_timestamp)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    detection_details = json.dumps({"added_by": request.added_by or "User reported whitelist"})
    now = datetime.now()
    cursor.execute(insert_query, (
        scan_id, request.url, 'completed', False, 'low', 0, 0, 0, True, 'clean', detection_details, now, now, now
    ))
    conn.commit()
    cursor.close()
    return {"success": True, "message": "URL reported as clean (whitelist)."}

@api_router.get("/user_scans")
def get_user_scans(email: str, limit: int = 20):
    """Get scan history for specific user"""
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    conn = get_mysql_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection error")
    
    cursor = conn.cursor(dictionary=True)
    select_query = """
    SELECT scan_id, url, status, is_malicious, threat_level, malicious_count,
           suspicious_count, total_engines, created_at, completed_at
    FROM scans 
    WHERE user_email = %s
    ORDER BY created_at DESC 
    LIMIT %s
    """
    cursor.execute(select_query, (email, limit))
    scans = cursor.fetchall()
    cursor.close()
    
    # Format results for frontend
    formatted_scans = []
    for scan in scans:
        formatted_scan = dict(scan)
        if scan['status'] == 'completed':
            formatted_scan['results'] = {
                'is_malicious': scan['is_malicious'],
                'threat_level': scan['threat_level'],
                'malicious_count': scan['malicious_count'],
                'suspicious_count': scan['suspicious_count'],
                'total_engines': scan['total_engines']
            }
        formatted_scans.append(formatted_scan)
    
    return formatted_scans

@api_router.get("/history")
async def get_scan_history(limit: int = 50):
    """Get recent scan history"""
    try:
        logger = logging.getLogger("history")
        logger.info("Getting scan history with limit: %s", limit)
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            select_query = """
            SELECT scan_id, url, status, is_malicious, threat_level, malicious_count,
                   suspicious_count, total_engines, created_at, completed_at
            FROM scans 
            ORDER BY created_at DESC 
            LIMIT %s
            """
            cursor.execute(select_query, (limit,))
            scans = cursor.fetchall()
            cursor.close()
            
            # Format results for frontend
            formatted_scans = []
            for scan in scans:
                formatted_scan = dict(scan)
                if scan['status'] == 'completed':
                    formatted_scan['results'] = {
                        'is_malicious': scan['is_malicious'],
                        'threat_level': scan['threat_level'],
                        'malicious_count': scan['malicious_count'],
                        'suspicious_count': scan['suspicious_count'],
                        'total_engines': scan['total_engines']
                    }
                formatted_scans.append(formatted_scan)
            
            return formatted_scans
        return []
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving history: {str(e)}")

@api_router.get("/stats")
async def get_statistics():
    """Get scanning statistics"""
    try:
        logger = logging.getLogger("stats")
        logger.info("Getting scanning statistics")
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            
            # Get overall statistics
            total_query = "SELECT COUNT(*) as total_scans FROM scans"
            cursor.execute(total_query)
            total_result = cursor.fetchone()
            total_scans = total_result['total_scans'] if total_result else 0
            
            malicious_query = "SELECT COUNT(*) as malicious_scans FROM scans WHERE is_malicious = TRUE"
            cursor.execute(malicious_query)
            malicious_result = cursor.fetchone()
            malicious_scans = malicious_result['malicious_scans'] if malicious_result else 0
            
            today_query = "SELECT COUNT(*) as today_scans FROM scans WHERE DATE(created_at) = CURDATE()"
            cursor.execute(today_query)
            today_result = cursor.fetchone()
            today_scans = today_result['today_scans'] if today_result else 0
            
            cursor.close()
            
            clean_scans = total_scans - malicious_scans
            detection_rate = (malicious_scans / total_scans * 100) if total_scans > 0 else 0
            
            return {
                'total_scans': total_scans,
                'malicious_detected': malicious_scans,
                'clean_scans': clean_scans,
                'today_scans': today_scans,
                'detection_rate': round(detection_rate, 2)
            }
        
        return {
            'total_scans': 0,
            'malicious_detected': 0,
            'clean_scans': 0,
            'today_scans': 0,
            'detection_rate': 0
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving stats: {str(e)}")

@api_router.get("/dashboard-stats")
async def get_dashboard_statistics():
    """Get dashboard statistics including URLs scanned, threats blocked, and user count"""
    try:
        logger = logging.getLogger("dashboard")
        logger.info("Getting dashboard statistics")
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            
            # Get total URLs scanned
            urls_query = "SELECT COUNT(*) as total_urls FROM scans WHERE status = 'completed'"
            cursor.execute(urls_query)
            urls_result = cursor.fetchone()
            urls_scanned = urls_result['total_urls'] if urls_result else 0
            
            # Get total threats blocked
            threats_query = "SELECT COUNT(*) as total_threats FROM scans WHERE is_malicious = TRUE AND status = 'completed'"
            cursor.execute(threats_query)
            threats_result = cursor.fetchone()
            threats_blocked = threats_result['total_threats'] if threats_result else 0
            
            # Get total users
            users_query = "SELECT COUNT(DISTINCT user_email) as total_users FROM scans WHERE user_email IS NOT NULL"
            cursor.execute(users_query)
            users_result = cursor.fetchone()
            users_count = users_result['total_users'] if users_result else 0
            
            cursor.close()
            
            return {
                'urls_scanned': urls_scanned,
                'threats_blocked': threats_blocked,
                'users': users_count,
                'uptime': '99.99 %'  # Always return 99.99%
            }
        
        return {
            'urls_scanned': 0,
            'threats_blocked': 0,
            'users': 0,
            'uptime': '99.99 %'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving dashboard stats: {str(e)}")

@api_router.get("/reports/summary")
async def get_reports_summary(limit: int = 100):
    """Get summary of scan reports for the reports page"""
    try:
        logger = logging.getLogger("reports")
        logger.info("Getting reports summary")
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            
            # Get recent scans with threat analysis
            select_query = """
            SELECT scan_id, url, status, is_malicious, threat_level, malicious_count,
                   suspicious_count, total_engines, created_at, completed_at, user_email
            FROM scans 
            WHERE status = 'completed'
            ORDER BY created_at DESC 
            LIMIT %s
            """
            cursor.execute(select_query, (limit,))
            scans = cursor.fetchall()
            
            # Get threat level distribution
            threat_query = """
            SELECT threat_level, COUNT(*) as count
            FROM scans 
            WHERE status = 'completed'
            GROUP BY threat_level
            """
            cursor.execute(threat_query)
            threat_distribution = cursor.fetchall()
            
            cursor.close()
            
            return {
                'recent_scans': scans,
                'threat_distribution': threat_distribution,
                'total_reports': len(scans)
            }
        
        return {'recent_scans': [], 'threat_distribution': [], 'total_reports': 0}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving reports summary: {str(e)}")

@api_router.get("/export/data")
async def export_scan_data(format: str = "json", limit: int = 1000):
    """Export scan data in various formats for the export page"""
    try:
        logger = logging.getLogger("export")
        logger.info(f"Exporting scan data in {format} format")
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            
            # Get scan data
            select_query = """
            SELECT scan_id, url, status, is_malicious, threat_level, malicious_count,
                   suspicious_count, total_engines, ssl_valid, domain_reputation,
                   created_at, completed_at, user_email
            FROM scans 
            ORDER BY created_at DESC 
            LIMIT %s
            """
            cursor.execute(select_query, (limit,))
            scans = cursor.fetchall()
            cursor.close()
            
            if format.lower() == "csv":
                # Convert to CSV format
                import csv
                import io
                output = io.StringIO()
                if scans:
                    writer = csv.DictWriter(output, fieldnames=scans[0].keys())
                    writer.writeheader()
                    writer.writerows(scans)
                
                return HTMLResponse(
                    content=output.getvalue(),
                    media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=scan_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
                )
            else:
                # Default to JSON
                return {
                    'export_format': 'json',
                    'export_timestamp': datetime.now().isoformat(),
                    'total_records': len(scans),
                    'data': scans
                }
        
        return {'error': 'Database connection failed'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error exporting data: {str(e)}")

@api_router.get("/features/list")
async def get_features_list():
    """Get list of available features for the features page"""
    try:
        features = {
            'core_features': [
                {
                    'name': 'Real-time URL Scanning',
                    'description': 'Instant analysis of URLs for malicious content and phishing attempts',
                    'status': 'active'
                },
                {
                    'name': 'ML-Powered Detection',
                    'description': 'Advanced machine learning models for threat detection',
                    'status': 'active'
                },
                {
                    'name': 'SSL Certificate Analysis',
                    'description': 'Comprehensive SSL/TLS certificate validation',
                    'status': 'active'
                },
                {
                    'name': 'Content Analysis',
                    'description': 'Deep analysis of webpage content for phishing indicators',
                    'status': 'active'
                }
            ],
            'security_features': [
                {
                    'name': 'VirusTotal Integration',
                    'description': 'Integration with VirusTotal for additional threat intelligence',
                    'status': 'active'
                },
                {
                    'name': 'Fallback Security Checks',
                    'description': 'Alternative security checks when external APIs are unavailable',
                    'status': 'active'
                },
                {
                    'name': 'Threat Scoring',
                    'description': 'Comprehensive threat scoring system',
                    'status': 'active'
                }
            ],
            'user_features': [
                {
                    'name': 'User Authentication',
                    'description': 'Secure user registration and login system',
                    'status': 'active'
                },
                {
                    'name': 'Scan History',
                    'description': 'Complete history of all scans performed',
                    'status': 'active'
                },
                {
                    'name': 'Profile Management',
                    'description': 'User profile and preference management',
                    'status': 'active'
                }
            ]
        }
        
        return features
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving features: {str(e)}")

@api_router.get("/health")
async def health_check():
    """Health check endpoint"""
    logger = logging.getLogger("health")
    logger.info("Running health check")
    conn = get_mysql_connection()
    database_status = "connected" if conn and conn.is_connected() else "disconnected"
    
    # Test database connection with a simple query
    db_test = "failed"
    if conn and conn.is_connected():
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            db_test = "passed"
        except Exception as e:
            db_test = f"failed: {str(e)}"
    
    # Check ML models status
    ml_status = "unknown"
    try:
        from .ml_integration import get_ml_engine
        ml_engine = get_ml_engine()
        ml_status_info = ml_engine.get_model_status()
        ml_status = {
            "url_classifier_trained": ml_status_info['url_classifier_trained'],
            "content_detector_trained": ml_status_info['content_detector_trained'],
            "models_available": ml_status_info['url_classifier_trained'] or ml_status_info['content_detector_trained']
        }
    except Exception as e:
        ml_status = f"error: {str(e)}"
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": database_status,
        "database_test": db_test,
        "database_type": "MySQL",
        "ml_models": ml_status
    }

@api_router.get("/docs")
async def get_api_documentation():
    """Get API documentation and available endpoints"""
    try:
        docs = {
            "api_name": "WebShield API",
            "version": "1.0.0",
            "description": "Real-time Fake Website & Malware Detection API",
            "endpoints": {
                "frontend_pages": [
                    {"path": "/", "description": "Main dashboard page"},
                    {"path": "/dashboard.html", "description": "User dashboard"},
                    {"path": "/scan_url.html", "description": "URL scanning interface"},
                    {"path": "/reports.html", "description": "Scan reports and analytics"},
                    {"path": "/features.html", "description": "Available features list"},
                    {"path": "/export.html", "description": "Data export interface"},
                    {"path": "/api-settings.html", "description": "API configuration settings"},
                    {"path": "/scan_report.html", "description": "Detailed scan report view"}
                ],
                "api_endpoints": [
                    {"path": "/api/scan", "method": "POST", "description": "Scan a URL for threats"},
                    {"path": "/api/reports/summary", "method": "GET", "description": "Get scan reports summary"},
                    {"path": "/api/export/data", "method": "GET", "description": "Export scan data"},
                    {"path": "/api/features/list", "method": "GET", "description": "Get available features"},
                    {"path": "/api/health", "method": "GET", "description": "API health check"},
                    {"path": "/api/stats", "method": "GET", "description": "Get scanning statistics"}
                ]
            }
        }
        return docs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving API documentation: {str(e)}")

# API Key Management Endpoints
@api_router.post("/keys/generate")
async def generate_api_key(request: ApiKeyRequest):
    """Generate a new API key for a user"""
    try:
        connection = get_mysql_connection()
        cursor = connection.cursor()
        
        # Generate API key
        api_key = f"ws_{hashlib.sha256(f'{request.name}{datetime.now().isoformat()}'.encode()).hexdigest()[:32]}"
        
        # Insert into database
        cursor.execute("""
            INSERT INTO api_keys (user_email, api_key, name, permissions, rate_limits, webhook_url, webhook_settings)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            request.name,  # Using name as user_email for now
            api_key,
            request.name,
            json.dumps(request.permissions or {}),
            json.dumps(request.rate_limits or {}),
            request.webhook_url,
            json.dumps(request.webhook_settings or {})
        ))
        
        connection.commit()
        cursor.close()
        connection.close()
        
        return {
            "api_key": api_key,
            "name": request.name,
            "created_at": datetime.now().isoformat(),
            "message": "API key generated successfully"
        }
        
    except Exception as e:
        logger.error(f"Database error in generate_api_key: {e}")
        raise HTTPException(status_code=500, detail="Database error")

@api_router.get("/keys/list")
async def list_api_keys(user_email: str):
    """List all API keys for a user"""
    try:
        connection = get_mysql_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id, api_key, name, permissions, rate_limits, webhook_url, 
                   is_active, created_at, last_used, usage_count
            FROM api_keys 
            WHERE user_email = %s
            ORDER BY created_at DESC
        """, (user_email,))
        
        keys = cursor.fetchall()
        cursor.close()
        connection.close()
        
        return {
            "user_email": user_email,
            "api_keys": keys,
            "total_keys": len(keys)
        }
        
    except Exception as e:
        logger.error(f"Database error in list_api_keys: {e}")
        raise HTTPException(status_code=500, detail="Database error")

@api_router.delete("/keys/{key_id}")
async def delete_api_key(key_id: int, user_email: str):
    """Delete an API key"""
    try:
        connection = get_mysql_connection()
        cursor = connection.cursor()
        
        cursor.execute("""
            DELETE FROM api_keys 
            WHERE id = %s AND user_email = %s
        """, (key_id, user_email))
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="API key not found")
        
        connection.commit()
        cursor.close()
        connection.close()
        
        return {"message": "API key deleted successfully"}
        
    except Exception as e:
        logger.error(f"Database error in delete_api_key: {e}")
        raise HTTPException(status_code=500, detail="Database error")

# API Settings Endpoints
@api_router.post("/settings/save")
async def save_api_settings(request: ApiSettingsRequest):
    """Save API settings for a user"""
    try:
        connection = get_mysql_connection()
        cursor = connection.cursor()
        
        # Check if user settings exist
        cursor.execute("SELECT id FROM user_settings WHERE user_email = %s", (request.notification_email,))
        existing = cursor.fetchone()
        
        api_settings = {
            "write_access": request.write_access,
            "admin_access": request.admin_access,
            "webhook_url": request.webhook_url,
            "webhook_scan_completed": request.webhook_scan_completed,
            "webhook_threat_detected": request.webhook_threat_detected,
            "webhook_usage_limit": request.webhook_usage_limit,
            "rate_limit_minute": request.rate_limit_minute,
            "rate_limit_hour": request.rate_limit_hour,
            "rate_limit_day": request.rate_limit_day,
            "email_api_usage": request.email_api_usage,
            "email_rate_limit": request.email_rate_limit,
            "email_security": request.email_security
        }
        
        if existing:
            cursor.execute("""
                UPDATE user_settings 
                SET api_settings = %s, updated_at = CURRENT_TIMESTAMP
                WHERE user_email = %s
            """, (json.dumps(api_settings), request.notification_email))
        else:
            cursor.execute("""
                INSERT INTO user_settings (user_email, api_settings)
                VALUES (%s, %s)
            """, (request.notification_email, json.dumps(api_settings)))
        
        connection.commit()
        cursor.close()
        connection.close()
        
        return {"message": "API settings saved successfully"}
        
    except Exception as e:
        logger.error(f"Database error in save_api_settings: {e}")
        raise HTTPException(status_code=500, detail="Database error")

@api_router.get("/settings/get")
async def get_api_settings(user_email: str):
    """Get API settings for a user"""
    try:
        connection = get_mysql_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT api_settings FROM user_settings 
            WHERE user_email = %s
        """, (user_email,))
        
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        
        if result and result['api_settings']:
            return json.loads(result['api_settings'])
        else:
            return {
                "write_access": False,
                "admin_access": False,
                "webhook_url": None,
                "webhook_scan_completed": True,
                "webhook_threat_detected": True,
                "webhook_usage_limit": False,
                "rate_limit_minute": 50,
                "rate_limit_hour": 1000,
                "rate_limit_day": 10000,
                "email_api_usage": True,
                "email_rate_limit": True,
                "email_security": True
            }
        
    except Exception as e:
        logger.error(f"Database error in get_api_settings: {e}")
        raise HTTPException(status_code=500, detail="Database error")

# Export Management Endpoints
@api_router.post("/export/create")
async def create_export(request: ExportRequest, background_tasks: BackgroundTasks):
    """Create a new export job"""
    try:
        connection = get_mysql_connection()
        cursor = connection.cursor()
        
        # Generate file name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"webshield_{request.export_type}_{timestamp}.{request.format}"
        
        # Insert export record
        cursor.execute("""
            INSERT INTO export_history (user_email, export_type, format, file_name, status)
            VALUES (%s, %s, %s, %s, 'pending')
        """, (request.user_email, request.export_type, request.format, file_name))
        
        export_id = cursor.lastrowid
        connection.commit()
        cursor.close()
        connection.close()
        
        # Start background export process
        from .export import process_export
        background_tasks.add_task(process_export, export_id, request)
        
        return {
            "export_id": export_id,
            "file_name": file_name,
            "status": "pending",
            "message": "Export job created successfully"
        }
        
    except Exception as e:
        logger.error(f"Database error in create_export: {e}")
        raise HTTPException(status_code=500, detail="Database error")

@api_router.get("/export/history")
async def get_export_history(user_email: str, limit: int = 10):
    """Get export history for a user"""
    try:
        connection = get_mysql_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id, export_type, format, file_name, file_size, status, 
                   created_at, completed_at
            FROM export_history 
            WHERE user_email = %s
            ORDER BY created_at DESC
            LIMIT %s
        """, (user_email, limit))
        
        exports = cursor.fetchall()
        cursor.close()
        connection.close()
        
        return {
            "user_email": user_email,
            "exports": exports,
            "total_exports": len(exports)
        }
        
    except Exception as e:
        logger.error(f"Database error in get_export_history: {e}")
        raise HTTPException(status_code=500, detail="Database error")

@api_router.get("/export/download/{export_id}")
async def download_export(export_id: int, user_email: str):
    """Download an exported file"""
    try:
        connection = get_mysql_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT file_name, file_path, status FROM export_history 
            WHERE id = %s AND user_email = %s
        """, (export_id, user_email))
        
        export = cursor.fetchone()
        cursor.close()
        connection.close()
        
        if not export:
            raise HTTPException(status_code=404, detail="Export not found")
        
        if export['status'] != 'completed':
            raise HTTPException(status_code=400, detail="Export not completed yet")
        
        # In a real implementation, you would serve the actual file
        # For now, we'll return a mock response
        return {
            "file_name": export['file_name'],
            "download_url": f"/api/export/files/{export_id}",
            "message": "File ready for download"
        }
        
    except Exception as e:
        logger.error(f"Database error in download_export: {e}")
        raise HTTPException(status_code=500, detail="Database error")

# Report Download Endpoint
@api_router.post("/reports/download")
async def download_report(request: DownloadReportRequest):
    """Download a specific scan report"""
    try:
        connection = get_mysql_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT scan_id, url, is_malicious, threat_level, malicious_count, 
                   suspicious_count, total_engines, detection_details, ssl_valid,
                   domain_reputation, content_analysis, scan_timestamp, created_at
            FROM scans 
            WHERE scan_id = %s
        """, (request.scan_id,))
        
        scan = cursor.fetchone()
        cursor.close()
        connection.close()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan report not found")
        
        if request.format.lower() == "json":
            return {
                "scan_report": scan,
                "format": "json",
                "download_url": f"/api/reports/{request.scan_id}/download.json"
            }
        elif request.format.lower() == "csv":
            csv_data = f"scan_id,url,is_malicious,threat_level,malicious_count,suspicious_count,total_engines,ssl_valid,domain_reputation,scan_timestamp\n"
            csv_data += f"{scan['scan_id']},{scan['url']},{scan['is_malicious']},{scan['threat_level']},{scan['malicious_count']},{scan['suspicious_count']},{scan['total_engines']},{scan['ssl_valid']},{scan['domain_reputation']},{scan['scan_timestamp']}\n"
            
            return {
                "scan_report": csv_data,
                "format": "csv",
                "download_url": f"/api/reports/{request.scan_id}/download.csv"
            }
        else:
            raise HTTPException(status_code=400, detail="Unsupported format. Use 'json' or 'csv'")
        
    except Exception as e:
        logger.error(f"Database error in download_report: {e}")
        raise HTTPException(status_code=500, detail="Database error")
