from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
import os
import logging

logger = logging.getLogger(__name__)

frontend_router = APIRouter(tags=["Frontend"])

@frontend_router.get("/", response_class=HTMLResponse)
async def serve_index():
    try:
        with open("frontend/index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>WebShield Frontend Not Found</h1><p>Please ensure frontend/index.html exists.</p>", status_code=404)

@frontend_router.get("/dashboard.html", response_class=HTMLResponse)
async def serve_dashboard_page():
    try:
        with open("frontend/dashboard.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Dashboard Page Not Found</h1>", status_code=404)

@frontend_router.get("/how-to-install.html", response_class=HTMLResponse)
async def serve_how_to_install_page():
    try:
        with open("frontend/how-to-install.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>How to Install Page Not Found</h1>", status_code=404)

@frontend_router.get("/login.html", response_class=HTMLResponse)
async def serve_login_page():
    try:
        with open("frontend/login.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Login Page Not Found</h1>", status_code=404)

@frontend_router.get("/register.html", response_class=HTMLResponse)
async def serve_register_page():
    try:
        with open("frontend/register.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Register Page Not Found</h1>", status_code=404)

@frontend_router.get("/profile.html", response_class=HTMLResponse)
async def serve_profile():
    try:
        with open("frontend/profile.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Profile Page Not Found</h1>", status_code=404)

@frontend_router.get("/debug_navigation.html", response_class=HTMLResponse)
async def serve_debug_navigation():
    try:
        with open("frontend/debug_navigation.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Debug Navigation Page Not Found</h1>", status_code=404)

@frontend_router.get("/test_navigation.html", response_class=HTMLResponse)
async def serve_test_navigation():
    try:
        with open("frontend/test_navigation.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Test Navigation Page Not Found</h1>", status_code=404)

@frontend_router.get("/scan_id.html", response_class=HTMLResponse)
async def serve_scan_id():
    try:
        with open("frontend/scan_id.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Scan ID Page Not Found</h1><p>Please ensure frontend/scan_id.html exists.</p>", status_code=404)

@frontend_router.get("/scan_report.html", response_class=HTMLResponse)
async def serve_scan_report(scan_id: str = None):
    """Serve scan report page with scan data"""
    try:
        # Read the template
        with open("frontend/scan_report.html", "r", encoding="utf-8") as f:
            template_content = f.read()
        
        # Always return the template - let JavaScript handle the scan_id parameter
        # This ensures the page loads properly regardless of how it's accessed
        return HTMLResponse(content=template_content)
            
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Scan Report Page Not Found</h1><p>Please ensure frontend/scan_report.html exists.</p>", status_code=404)
    except Exception as e:
        logger.error(f"Error rendering scan report: {e}")
        return HTMLResponse(content=f"<h1>Error Loading Scan Report</h1><p>{str(e)}</p>", status_code=500)

@frontend_router.get("/scan_url.html", response_class=HTMLResponse)
async def serve_scan_url_page():
    """Serve the scan URL page"""
    try:
        with open("frontend/scan-url.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Scan URL Page Not Found</h1><p>Please ensure frontend/scan-url.html exists.</p>", status_code=404)

@frontend_router.get("/reports.html", response_class=HTMLResponse)
async def serve_reports_page():
    """Serve the reports page"""
    try:
        with open("frontend/reports.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Reports Page Not Found</h1><p>Please ensure frontend/reports.html exists.</p>", status_code=404)

@frontend_router.get("/features.html", response_class=HTMLResponse)
async def serve_features_page():
    """Serve the features page"""
    try:
        with open("frontend/features.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Features Page Not Found</h1><p>Please ensure frontend/features.html exists.</p>", status_code=404)

@frontend_router.get("/export.html", response_class=HTMLResponse)
async def serve_export_page():
    """Serve the export page"""
    try:
        with open("frontend/export.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Export Page Not Found</h1><p>Please ensure frontend/export.html exists.</p>", status_code=404)

@frontend_router.get("/api-settings.html", response_class=HTMLResponse)
async def serve_api_settings_page():
    """Serve the API settings page"""
    try:
        with open("frontend/api-settings.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>API Settings Page Not Found</h1><p>Please ensure frontend/api-settings.html exists.</p>", status_code=404)

@frontend_router.get("/{page_name}.html", response_class=HTMLResponse)
async def serve_generic_html_page(page_name: str):
    """Generic route to serve any HTML page from the frontend directory"""
    try:
        file_path = f"frontend/{page_name}.html"
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail=f"Page {page_name}.html not found")
        
        with open(file_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error serving page {page_name}.html: {e}")
        raise HTTPException(status_code=500, detail=f"Error loading page: {str(e)}")

@frontend_router.get("/config.js")
def serve_config_js():
    """Serve the config.js file"""
    try:
        with open("frontend/config.js", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), media_type="application/javascript")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Config file not found")

@frontend_router.get("/static/{file_path:path}")
async def serve_static_files(file_path: str):
    """Serve static files from the frontend directory"""
    try:
        file_path = os.path.join("frontend", file_path)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="File not found")
        
        # Determine content type based on file extension
        content_type = "text/plain"
        if file_path.endswith('.css'):
            content_type = "text/css"
        elif file_path.endswith('.js'):
            content_type = "application/javascript"
        elif file_path.endswith('.png'):
            content_type = "image/png"
        elif file_path.endswith('.jpg') or file_path.endswith('.jpeg'):
            content_type = "image/jpeg"
        elif file_path.endswith('.gif'):
            content_type = "image/gif"
        elif file_path.endswith('.svg'):
            content_type = "image/svg+xml"
        elif file_path.endswith('.ico'):
            content_type = "image/x-icon"
        
        # Handle binary files properly
        if content_type.startswith('image/'):
            with open(file_path, "rb") as f:
                return FileResponse(file_path, media_type=content_type)
        else:
            with open(file_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read(), media_type=content_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error serving file: {str(e)}")

@frontend_router.get("/favicon.ico")
async def serve_favicon():
    """Serve the favicon file"""
    try:
        favicon_path = "frontend/favicon.ico"
        if os.path.exists(favicon_path):
            return FileResponse(favicon_path, media_type="image/x-icon")
        else:
            # Return a default favicon if none exists
            return HTMLResponse(content="", status_code=404)
    except Exception as e:
        return HTMLResponse(content="", status_code=500)

@frontend_router.get("/profile_pics/{filename}")
def get_profile_picture(filename: str):
    """Serve profile pictures"""
    filepath = os.path.join("profile_pics", filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Profile picture not found")
    return FileResponse(filepath)

@frontend_router.get("/test_scan.html", response_class=HTMLResponse)
async def serve_test_scan():
    try:
        with open("frontend/test_scan.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Test Scan Page Not Found</h1><p>Please ensure frontend/test_scan.html exists.</p>", status_code=404)
