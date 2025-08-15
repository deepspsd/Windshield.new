import logging
import json
import csv
import os
from datetime import datetime
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
import sqlite3
from pathlib import Path

# Configure logging
logger = logging.getLogger(__name__)

# Create export router
export_router = APIRouter(prefix="/api/export", tags=["Export"])

def get_db_connection():
    """Get database connection"""
    return sqlite3.connect("windshield.db")

async def process_export(export_id: int, request: Dict[str, Any]):
    """Process export in background"""
    try:
        logger.info(f"Starting export process for export_id: {export_id}")
        
        # Get export details from database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT user_email, export_type, format, file_name 
            FROM export_history 
            WHERE id = ?
        """, (export_id,))
        
        export_data = cursor.fetchone()
        if not export_data:
            logger.error(f"Export record not found for id: {export_id}")
            return
            
        user_email, export_type, format_type, file_name = export_data
        
        # Create exports directory if it doesn't exist
        exports_dir = Path("exports")
        exports_dir.mkdir(exist_ok=True)
        
        file_path = exports_dir / file_name
        
        # Get scan data based on export type
        if export_type == "scans":
            data = await export_scan_data(format_type)
        elif export_type == "reports":
            data = await export_report_data(format_type)
        else:
            data = await export_all_data(format_type)
        
        # Write data to file
        if format_type == "json":
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
        elif format_type == "csv":
            if data and isinstance(data, list) and len(data) > 0:
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    writer.writeheader()
                    writer.writerows(data)
            else:
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    f.write("No data available\n")
        
        # Update export status
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        cursor.execute("""
            UPDATE export_history 
            SET status = 'completed', file_path = ?, file_size = ?, completed_at = ?
            WHERE id = ?
        """, (str(file_path), file_size, datetime.now().isoformat(), export_id))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Export completed successfully for export_id: {export_id}")
        
    except Exception as e:
        logger.error(f"Error processing export {export_id}: {str(e)}")
        
        # Update export status to failed
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE export_history 
                SET status = 'failed', error_message = ?
                WHERE id = ?
            """, (str(e), export_id))
            conn.commit()
            conn.close()
        except Exception as update_error:
            logger.error(f"Error updating export status: {update_error}")

async def export_scan_data(format_type: str = "json"):
    """Export scan data"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, url, scan_date, risk_level, category, 
                   is_safe, scan_result, created_at
            FROM scan_history
            ORDER BY scan_date DESC
        """)
        
        scans = cursor.fetchall()
        conn.close()
        
        if format_type == "json":
            return [
                {
                    "id": scan[0],
                    "url": scan[1],
                    "scan_date": scan[2],
                    "risk_level": scan[3],
                    "category": scan[4],
                    "is_safe": scan[5],
                    "scan_result": scan[6],
                    "created_at": scan[7]
                }
                for scan in scans
            ]
        else:
            return scans
            
    except Exception as e:
        logger.error(f"Error exporting scan data: {e}")
        raise HTTPException(status_code=500, detail=f"Error exporting scan data: {str(e)}")

async def export_report_data(format_type: str = "json"):
    """Export report data"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, report_type, report_data, created_at, user_email
            FROM reports
            ORDER BY created_at DESC
        """)
        
        reports = cursor.fetchall()
        conn.close()
        
        if format_type == "json":
            return [
                {
                    "id": report[0],
                    "report_type": report[1],
                    "report_data": report[2],
                    "created_at": report[3],
                    "user_email": report[4]
                }
                for report in reports
            ]
        else:
            return reports
            
    except Exception as e:
        logger.error(f"Error exporting report data: {e}")
        raise HTTPException(status_code=500, detail=f"Error exporting report data: {str(e)}")

async def export_all_data(format_type: str = "json"):
    """Export all data"""
    try:
        scan_data = await export_scan_data(format_type)
        report_data = await export_report_data(format_type)
        
        return {
            "scans": scan_data,
            "reports": report_data,
            "export_timestamp": datetime.now().isoformat(),
            "total_scans": len(scan_data),
            "total_reports": len(report_data)
        }
        
    except Exception as e:
        logger.error(f"Error exporting all data: {e}")
        raise HTTPException(status_code=500, detail=f"Error exporting all data: {str(e)}")

@export_router.get("/status/{export_id}")
async def get_export_status(export_id: int):
    """Get export status"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, export_type, format, file_name, file_size, status, 
                   created_at, completed_at, error_message
            FROM export_history
            WHERE id = ?
        """, (export_id,))
        
        export = cursor.fetchone()
        conn.close()
        
        if not export:
            raise HTTPException(status_code=404, detail="Export not found")
        
        return {
            "id": export[0],
            "export_type": export[1],
            "format": export[2],
            "file_name": export[3],
            "file_size": export[4],
            "status": export[5],
            "created_at": export[6],
            "completed_at": export[7],
            "error_message": export[8]
        }
        
    except Exception as e:
        logger.error(f"Error getting export status: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting export status: {str(e)}")

@export_router.get("/files/{export_id}")
async def download_export_file(export_id: int):
    """Download export file"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT file_name, file_path, status FROM export_history
            WHERE id = ?
        """, (export_id,))
        
        export = cursor.fetchone()
        conn.close()
        
        if not export:
            raise HTTPException(status_code=404, detail="Export not found")
        
        if export[2] != 'completed':
            raise HTTPException(status_code=400, detail="Export not completed yet")
        
        file_path = Path(export[1])
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Export file not found")
        
        # Return file path for download
        return {
            "file_name": export[0],
            "file_path": str(file_path),
            "file_size": file_path.stat().st_size
        }
        
    except Exception as e:
        logger.error(f"Error downloading export file: {e}")
        raise HTTPException(status_code=500, detail=f"Error downloading export file: {str(e)}")
