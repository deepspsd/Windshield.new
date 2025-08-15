from fastapi import APIRouter, HTTPException
import re
import time
import json
import logging
from datetime import datetime
from uuid import uuid4
from threading import Thread
import asyncio
from .models import URLScanRequest, ThreatReport, ScanResult
from .db import get_mysql_connection
from .utils import WebShieldDetector

logger = logging.getLogger(__name__)

scan_router = APIRouter(prefix="/api", tags=["Scanning"])

# In-memory cache for scan results (simple dict with expiry)
SCAN_CACHE = {}
CACHE_TTL = 300  # 5 minutes (faster cache refresh)
SCAN_IN_PROGRESS = {}  # url: scan_id

def get_cached_scan(url):
    entry = SCAN_CACHE.get(url)
    if entry and time.time() - entry['ts'] < CACHE_TTL:
        return entry['result']
    return None

def set_cached_scan(url, result):
    SCAN_CACHE[url] = {'result': result, 'ts': time.time()}

def generate_scan_id():
    return str(uuid4())

async def _do_scan(url: str, scan_id: str):
    import logging
    logger = logging.getLogger("scan")
    start_time = time.time()
    try:
        async with WebShieldDetector() as detector_instance:
            async def with_timeout(coro, timeout, label):
                t0 = time.time()
                try:
                    result = await asyncio.wait_for(coro, timeout=timeout)
                    logger.info(f"{label} completed in {time.time()-t0:.2f}s")
                    return result
                except Exception as e:
                    logger.warning(f"{label} failed or timed out: {e}")
                    return {'error': str(e)}
            url_analysis_task = detector_instance.analyze_url_patterns(url)
            ssl_task = with_timeout(detector_instance.analyze_ssl_certificate(url), 3.0, 'SSL')
            content_task = with_timeout(detector_instance.analyze_content(url, max_bytes=10*1024), 3.0, 'Content')
            vt_task = with_timeout(detector_instance.check_virustotal(url), 2.0, 'VirusTotal')
            url_analysis, ssl_analysis, content_analysis, vt_analysis = await asyncio.gather(
                url_analysis_task, ssl_task, content_task, vt_task, return_exceptions=True
            )
            logger.info(f"Scan results for {url}: url_analysis={url_analysis}, ssl_analysis={ssl_analysis}, content_analysis={content_analysis}, vt_analysis={vt_analysis}")
            
            # Handle URL analysis with fallback
            if isinstance(url_analysis, Exception):
                logger.error(f"URL analysis failed with exception: {url_analysis}")
                url_analysis = {
                    'error': f'URL analysis failed: {str(url_analysis)}',
                    'suspicious_score': 0,
                    'detected_issues': [],
                    'domain': 'N/A',
                    'is_suspicious': False
                }
            elif not isinstance(url_analysis, dict):
                logger.error(f"URL analysis returned invalid type: {type(url_analysis)}")
                url_analysis = {
                    'error': 'URL analysis returned invalid data',
                    'suspicious_score': 0,
                    'detected_issues': [],
                    'domain': 'N/A',
                    'is_suspicious': False
                }
            
            # Handle content analysis with fallback
            if isinstance(content_analysis, Exception):
                logger.error(f"Content analysis failed with exception: {content_analysis}")
                content_analysis = {
                    'error': f'Content analysis failed: {str(content_analysis)}',
                    'phishing_score': 0,
                    'detected_indicators': [],
                    'is_suspicious': False,
                    'content_length': 0
                }
            elif not isinstance(content_analysis, dict):
                logger.error(f"Content analysis returned invalid type: {type(content_analysis)}")
                content_analysis = {
                    'error': 'Content analysis returned invalid data',
                    'phishing_score': 0,
                    'detected_indicators': [],
                    'is_suspicious': False,
                    'content_length': 0
                }
            
            # Handle VirusTotal analysis with fallback
            malicious_count = 0
            suspicious_count = 0
            total_engines = 0
            vt_source = "VirusTotal"
            
            if isinstance(vt_analysis, dict) and 'error' not in vt_analysis:
                malicious_count = vt_analysis.get('malicious_count', 0)
                suspicious_count = vt_analysis.get('suspicious_count', 0)
                total_engines = vt_analysis.get('total_engines', 0)
                
                # Check if fallback checks were used
                if vt_analysis.get('fallback_checks', False):
                    vt_source = "Fallback Security Checks"
                    logger.info(f"VirusTotal unavailable for {url}, using fallback security checks")
                else:
                    logger.info(f"VirusTotal analysis completed for {url}")
            else:
                # VirusTotal failed, use other security checks
                logger.warning(f"VirusTotal analysis failed for {url}, using other security checks")
                # Set default values for display
                malicious_count = 0
                suspicious_count = 0
                total_engines = 0
                vt_source = "Fallback Security Checks"
            
            threat_score = 0
            if isinstance(url_analysis, dict):
                threat_score += url_analysis.get('suspicious_score', 0)
            if isinstance(content_analysis, dict):
                threat_score += content_analysis.get('phishing_score', 0)
            if isinstance(ssl_analysis, dict):
                # Use the new SSL threat scoring system
                ssl_threat = ssl_analysis.get('threat_score', 0)
                threat_score += ssl_threat
                
                # Additional penalty for intentionally insecure sites
                if ssl_analysis.get('is_intentionally_insecure', False):
                    threat_score += 15  # Extra penalty for sites that are intentionally insecure
            
            # Add VirusTotal scores if available
            threat_score += malicious_count * 10 + suspicious_count * 5
            
            # Determine threat level based on available data
            # Check for SSL/security issues first (ignore network/errors)
            ssl_issues = False
            if isinstance(ssl_analysis, dict):
                has_ssl_error = 'error' in ssl_analysis
                ssl_issues = (
                    (not has_ssl_error and not ssl_analysis.get('valid', True)) or 
                    ssl_analysis.get('is_intentionally_insecure', False) or
                    ssl_analysis.get('threat_score', 0) > 20
                )
            
            # Enhanced threat level calculation - more conservative thresholds
            if threat_score > 80 or malicious_count > 5 or ssl_issues:
                threat_level = 'high'
                is_malicious = True
            elif threat_score > 50 or malicious_count > 2 or suspicious_count > 3 or (isinstance(ssl_analysis, dict) and not ssl_analysis.get('valid', True) and not ssl_analysis.get('is_intentionally_insecure', False)):
                threat_level = 'medium'
                is_malicious = True
            else:
                threat_level = 'low'
                is_malicious = False
            
            # Guarantee a valid ScanResult even if all checks are empty or error
            detection_details = {
                'url_analysis': url_analysis if isinstance(url_analysis, dict) else {'error': str(url_analysis)},
                'ssl_analysis': ssl_analysis if isinstance(ssl_analysis, dict) else {'error': str(ssl_analysis)},
                'content_analysis': content_analysis if isinstance(content_analysis, dict) else {'error': str(content_analysis)},
                'virustotal_analysis': vt_analysis if isinstance(vt_analysis, dict) else {'error': str(vt_analysis)},
                'database_health': {'database': 'connected' if get_mysql_connection() and get_mysql_connection().is_connected() else 'disconnected'}
            }
            
            # Ensure at least one field is always present in detection_details
            if not detection_details['url_analysis']:
                detection_details['url_analysis'] = {'info': 'No suspicious patterns found'}
            if not detection_details['ssl_analysis']:
                detection_details['ssl_analysis'] = {'info': 'No SSL issues found'}
            if not detection_details['content_analysis']:
                detection_details['content_analysis'] = {'info': 'No phishing indicators found'}
            if not detection_details['virustotal_analysis']:
                detection_details['virustotal_analysis'] = {'info': 'VirusTotal analysis unavailable - using other security checks'}
            
            # Add information about which security checks were used
            detection_details['vt_source'] = vt_source
            result = ScanResult(
                url=url,
                is_malicious=is_malicious,
                threat_level=threat_level,
                malicious_count=malicious_count,
                suspicious_count=suspicious_count,
                total_engines=total_engines,
                detection_details=detection_details,
                # Treat network/timeout errors as unknown rather than invalid to avoid false negatives
                ssl_valid=(
                    (False if not isinstance(ssl_analysis, dict) else (
                        True if 'error' in ssl_analysis else ssl_analysis.get('valid', False)
                    ))
                ),
                domain_reputation='malicious' if is_malicious else 'clean',
                content_analysis=content_analysis if isinstance(content_analysis, dict) else {},
                scan_timestamp=datetime.now()
            )
            conn = get_mysql_connection()
            if conn:
                cursor = conn.cursor()
                logger.info(f"Updating scan {scan_id} status to completed")
                update_query = """
                UPDATE scans SET 
                    status = %s, 
                    is_malicious = %s,
                    threat_level = %s,
                    malicious_count = %s,
                    suspicious_count = %s,
                    total_engines = %s,
                    ssl_valid = %s,
                    domain_reputation = %s,
                    detection_details = %s,
                    completed_at = %s,
                    scan_timestamp = %s
                WHERE scan_id = %s
                """
                try:
                    cursor.execute(update_query, (
                        'completed', is_malicious, threat_level, malicious_count,
                        suspicious_count, total_engines, ssl_analysis.get('valid', False),
                        'malicious' if is_malicious else 'clean',
                        json.dumps(result.detection_details), datetime.now(),
                        result.scan_timestamp, scan_id
                    ))
                    conn.commit()
                    logger.info(f"Successfully updated scan {scan_id} to completed status")
                except Exception as e:
                    logger.error(f"Failed to update scan {scan_id}: {e}")
                    conn.rollback()
                finally:
                    cursor.close()
            else:
                logger.error(f"No database connection available for scan {scan_id} completion")
            logger.info(f"Total scan time: {time.time()-start_time:.2f}s")
            resp = ThreatReport(
                scan_id=scan_id,
                url=url,
                status='completed',
                results=result
            )
            set_cached_scan(url, resp)
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        # Always store a completed scan result, even on error
        detection_details = {
            'url_analysis': {'error': 'Scan failed'},
            'ssl_analysis': {'error': 'Scan failed'},
            'content_analysis': {'error': 'Scan failed'},
            'virustotal_analysis': {'error': 'Scan failed'},
            'database_health': {'database': 'error'},
            'vt_source': 'Scan Failed'
        }
        result = ScanResult(
            url=url,
            is_malicious=False,
            threat_level='low',
            malicious_count=0,
            suspicious_count=0,
            total_engines=0,
            detection_details=detection_details,
            ssl_valid=False,
            domain_reputation='unknown',
            content_analysis={},
            scan_timestamp=datetime.now()
        )
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor()
            logger.info(f"Setting scan {scan_id} status to completed (error case)")
            update_query = """
            UPDATE scans SET status = %s, detection_details = %s, completed_at = %s, scan_timestamp = %s WHERE scan_id = %s
            """
            try:
                cursor.execute(update_query, ('completed', json.dumps(result.detection_details), datetime.now(), result.scan_timestamp, scan_id))
                conn.commit()
                logger.info(f"Successfully updated scan {scan_id} to completed status (error case)")
            except Exception as e:
                logger.error(f"Failed to update scan {scan_id} in error case: {e}")
                conn.rollback()
            finally:
                cursor.close()
        else:
            logger.error(f"No database connection available for scan {scan_id} error handling")
        resp = ThreatReport(
            scan_id=scan_id,
            url=url,
            status='completed',
            results=result
        )
        set_cached_scan(url, resp)
    finally:
        logger.info(f"Total scan time: {time.time()-start_time:.2f}s")
        SCAN_IN_PROGRESS.pop(url, None)

@scan_router.get("/test-scan-endpoint")
async def test_scan_endpoint():
    """Test endpoint to verify scan endpoint is working."""
    try:
        # Test scan ID generation
        scan_id = generate_scan_id()
        
        # Test URL processing
        test_url = "https://example.com"
        url = str(test_url).strip()
        
        return {
            "status": "working",
            "scan_id": scan_id,
            "url_processing": url,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Test scan endpoint failed: {e}")
        return {"error": str(e)}

@scan_router.get("/test-scan-id")
async def test_scan_id_generation():
    """Test endpoint to verify scan ID generation."""
    try:
        scan_id = generate_scan_id()
        logger.info(f"Generated test scan ID: {scan_id}")
        return {
            "scan_id": scan_id,
            "scan_id_type": str(type(scan_id)),
            "scan_id_length": len(scan_id),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Test scan ID generation failed: {e}")
        return {"error": str(e)}

@scan_router.get("/health")
async def health_check():
    """Health check endpoint for the scanning service."""
    try:
        conn = get_mysql_connection()
        db_status = "connected" if conn and conn.is_connected() else "disconnected"
        if conn:
            conn.close()
        
        return {
            "status": "healthy",
            "database": db_status,
            "scan_cache_size": len(SCAN_CACHE),
            "scans_in_progress": len(SCAN_IN_PROGRESS),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

@scan_router.post("/scan", response_model=ThreatReport)
async def scan_url(request: URLScanRequest):
    logger = logging.getLogger("scan")
    logger.info("Scanning URL: %s", request.url)
    url = str(request.url).strip()
    # Auto-prepend https:// if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    # Validate URL format (basic check)
    url_pattern = re.compile(r'^https?://([\w.-]+)(:[0-9]+)?(/.*)?$')
    if not url_pattern.match(url):
        raise HTTPException(status_code=400, detail="Invalid or unsupported URL format. Please enter a valid http or https URL.")
    
    # Check cache first
    cached = get_cached_scan(url)
    if cached:
        logger.info(f"Cache hit for {url}")
        return cached
    
    # Check if URL is already being scanned
    if url in SCAN_IN_PROGRESS:
        scan_id = SCAN_IN_PROGRESS[url]
        logger.info(f"URL {url} already being scanned with ID: {scan_id}")
        return ThreatReport(scan_id=scan_id, url=url, status='processing', results=None)
    
    # Generate new scan ID
    scan_id = generate_scan_id()
    logger.info(f"Generated scan ID: {scan_id}")
    logger.info(f"Scan ID type: {type(scan_id)}")
    logger.info(f"Scan ID length: {len(scan_id)}")
    logger.info(f"Starting new scan for {url} with ID: {scan_id}")
    
    # Add to in-progress tracking
    SCAN_IN_PROGRESS[url] = scan_id
    
    # Insert processing status in DB
    conn = get_mysql_connection()
    if conn:
        cursor = conn.cursor()
        logger.info(f"Inserting scan into database: scan_id={scan_id}, url={url}, user_email={request.user_email}")
        insert_query = """
        INSERT INTO scans (scan_id, url, status, created_at, user_email)
        VALUES (%s, %s, %s, %s, %s)
        """
        try:
            cursor.execute(insert_query, (scan_id, url, 'processing', datetime.now(), request.user_email))
            conn.commit()
            logger.info(f"Successfully inserted scan {scan_id} into database")
        except Exception as e:
            logger.error(f"Failed to insert scan {scan_id}: {e}")
            conn.rollback()
            # Remove from in-progress if DB insert failed
            SCAN_IN_PROGRESS.pop(url, None)
            raise HTTPException(status_code=500, detail="Failed to start scan. Please try again.")
        finally:
            cursor.close()
    else:
        logger.error("No database connection available for scan insertion")
        # Remove from in-progress if no DB connection
        SCAN_IN_PROGRESS.pop(url, None)
        raise HTTPException(status_code=500, detail="Database connection error. Please try again.")
    
    def run_scan():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(_do_scan(url, scan_id))
        except Exception as e:
            logger.error(f"Background scan error: {e}")
        finally:
            # Always clean up the in-progress tracking
            if url in SCAN_IN_PROGRESS and SCAN_IN_PROGRESS[url] == scan_id:
                SCAN_IN_PROGRESS.pop(url, None)
                logger.info(f"Cleaned up scan tracking for {url}")
    
    Thread(target=run_scan, daemon=True).start()
    
    # Always return a valid response with scan_id
    response = ThreatReport(scan_id=scan_id, url=url, status='processing', results=None)
    logger.info(f"Returning scan response: {response}")
    logger.info(f"Response scan_id: {response.scan_id}")
    logger.info(f"Response scan_id type: {type(response.scan_id)}")
    return response

@scan_router.get("/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Get scan results by ID. Always return a valid 'results' object for completed scans."""
    try:
        logger = logging.getLogger("scan")
        logger.info("Getting scan result for ID: %s", scan_id)
        conn = get_mysql_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            select_query = """
            SELECT scan_id, url, status, is_malicious, threat_level, malicious_count,
                   suspicious_count, total_engines, ssl_valid, domain_reputation,
                   detection_details, created_at, completed_at, scan_timestamp
            FROM scans WHERE scan_id = %s
            """
            cursor.execute(select_query, (scan_id,))
            scan = cursor.fetchone()
            cursor.close()
            
            # Debug logging
            logger.info(f"Looking for scan_id: {scan_id}")
            if scan:
                logger.info(f"Found scan: {scan['scan_id']}, status: {scan['status']}")
            else:
                logger.warning(f"Scan not found: {scan_id}")
            
            if scan:
                # Convert detection_details from JSON string to dict
                if scan['detection_details']:
                    scan['detection_details'] = json.loads(scan['detection_details'])
                # Always return a valid results object for completed scans
                if scan['status'] == 'completed':
                    # Fallback: if detection_details or results are missing, return a default clean result
                    detection_details = scan['detection_details'] if scan['detection_details'] else {
                        'url_analysis': {'info': 'No suspicious patterns found'},
                        'ssl_analysis': {'info': 'No SSL issues found'},
                        'content_analysis': {'info': 'No phishing indicators found'},
                        'virustotal_analysis': {'info': 'No VirusTotal data'},
                        'database_health': {'database': 'unknown'}
                    }
                    return {
                        'scan_id': scan['scan_id'],
                        'url': scan['url'],
                        'status': scan['status'],
                        'results': {
                            'url': scan['url'],
                            'is_malicious': scan.get('is_malicious', False),
                            'threat_level': scan.get('threat_level', 'low'),
                            'malicious_count': scan.get('malicious_count', 0),
                            'suspicious_count': scan.get('suspicious_count', 0),
                            'total_engines': scan.get('total_engines', 0),
                            'detection_details': detection_details,
                            'ssl_valid': scan.get('ssl_valid', False),
                            'domain_reputation': scan.get('domain_reputation', 'unknown'),
                            'content_analysis': detection_details.get('content_analysis', {}),
                            'scan_timestamp': scan.get('scan_timestamp') or scan.get('completed_at')
                        }
                    }
                else:
                    # Scan is processing or errored
                    return {
                        'scan_id': scan['scan_id'],
                        'url': scan['url'],
                        'status': scan['status'],
                        'results': None
                    }
            else:
                # Scan not found in database
                raise HTTPException(status_code=404, detail="Scan not found")
        else:
            # Database connection failed
            raise HTTPException(status_code=500, detail="Database connection failed")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving scan {scan_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error retrieving scan: {str(e)}")
