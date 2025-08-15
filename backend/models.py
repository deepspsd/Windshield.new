from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Authentication Models
class RegisterRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password")
    confirm_password: str = Field(..., description="Password confirmation")

class LoginRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password")

# API Models
class ApiKeyRequest(BaseModel):
    user_email: str = Field(..., description="User email address")
    api_name: str = Field(..., description="Name for the API key")
    permissions: List[str] = Field(default=["read", "scan"], description="API key permissions")

class ApiSettingsRequest(BaseModel):
    user_email: str = Field(..., description="User email address")
    settings: Dict[str, Any] = Field(..., description="API settings configuration")

class ReportRequest(BaseModel):
    url: HttpUrl = Field(..., description="URL to report")
    report_type: str = Field(..., description="Type of report (blacklist/whitelist)")
    reason: Optional[str] = Field(None, description="Reason for reporting")
    user_email: Optional[str] = Field(None, description="User email address")

class DownloadReportRequest(BaseModel):
    report_id: int = Field(..., description="Report ID to download")
    user_email: str = Field(..., description="User email address")

class ExportRequest(BaseModel):
    user_email: str = Field(..., description="User email address")
    export_type: str = Field(..., description="Type of data to export (scans/reports/all)")
    format: str = Field(default="json", description="Export format (json/csv)")

# Scan Models
class URLScanRequest(BaseModel):
    url: HttpUrl = Field(..., description="URL to scan")
    user_email: Optional[str] = Field(None, description="User email address")
    scan_type: Optional[str] = Field("full", description="Type of scan to perform")

class ScanResult(BaseModel):
    url: str = Field(..., description="Scanned URL")
    is_malicious: bool = Field(..., description="Whether the URL is malicious")
    threat_level: str = Field(..., description="Threat level (low/medium/high)")
    malicious_count: int = Field(default=0, description="Number of malicious detections")
    suspicious_count: int = Field(default=0, description="Number of suspicious detections")
    total_engines: int = Field(default=0, description="Total number of engines checked")
    detection_details: Dict[str, Any] = Field(default_factory=dict, description="Detailed detection results")
    ssl_valid: bool = Field(default=False, description="SSL certificate validity")
    domain_reputation: str = Field(default="unknown", description="Domain reputation")
    content_analysis: Dict[str, Any] = Field(default_factory=dict, description="Content analysis results")
    scan_timestamp: Optional[datetime] = Field(None, description="Scan timestamp")
    
    # Legacy fields for backward compatibility
    scan_id: Optional[str] = Field(None, description="Unique scan identifier")
    status: Optional[str] = Field(None, description="Scan status")
    risk_level: Optional[str] = Field(None, description="Risk level assessment")
    category: Optional[str] = Field(None, description="Threat category")
    is_safe: Optional[bool] = Field(None, description="Safety assessment")
    scan_result: Optional[Dict[str, Any]] = Field(None, description="Detailed scan results")
    created_at: Optional[datetime] = Field(None, description="Scan creation timestamp")
    completed_at: Optional[datetime] = Field(None, description="Scan completion timestamp")

class ThreatReport(BaseModel):
    scan_id: str = Field(..., description="Unique scan identifier")
    url: str = Field(..., description="Scanned URL")
    status: str = Field(..., description="Scan status")
    results: Optional[ScanResult] = Field(None, description="Scan results")
    error_message: Optional[str] = Field(None, description="Error message if scan failed")

# Database Models
class User(BaseModel):
    id: Optional[int] = Field(None, description="User ID")
    email: str = Field(..., description="User email address")
    password_hash: str = Field(..., description="Hashed password")
    created_at: Optional[datetime] = Field(None, description="User creation timestamp")
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")
    is_active: bool = Field(default=True, description="User active status")

class ScanHistory(BaseModel):
    id: Optional[int] = Field(None, description="Scan history ID")
    url: str = Field(..., description="Scanned URL")
    scan_date: datetime = Field(..., description="Scan date")
    risk_level: Optional[str] = Field(None, description="Risk level")
    category: Optional[str] = Field(None, description="Threat category")
    is_safe: Optional[bool] = Field(None, description="Safety assessment")
    scan_result: Optional[Dict[str, Any]] = Field(None, description="Scan results")
    user_email: Optional[str] = Field(None, description="User email")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")

class ApiKey(BaseModel):
    id: Optional[int] = Field(None, description="API key ID")
    user_email: str = Field(..., description="User email")
    api_key: str = Field(..., description="API key hash")
    api_name: str = Field(..., description="API key name")
    permissions: str = Field(..., description="Permissions JSON string")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    last_used: Optional[datetime] = Field(None, description="Last usage timestamp")
    is_active: bool = Field(default=True, description="API key active status")

class ExportHistory(BaseModel):
    id: Optional[int] = Field(None, description="Export ID")
    user_email: str = Field(..., description="User email")
    export_type: str = Field(..., description="Export type")
    format: str = Field(..., description="Export format")
    file_name: Optional[str] = Field(None, description="Export file name")
    file_path: Optional[str] = Field(None, description="Export file path")
    file_size: Optional[int] = Field(None, description="Export file size")
    status: str = Field(default="pending", description="Export status")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    completed_at: Optional[datetime] = Field(None, description="Completion timestamp")
    error_message: Optional[str] = Field(None, description="Error message")

# Response Models
class ApiResponse(BaseModel):
    success: bool = Field(..., description="Request success status")
    message: str = Field(..., description="Response message")
    data: Optional[Dict[str, Any]] = Field(None, description="Response data")

class ScanResponse(BaseModel):
    success: bool = Field(..., description="Scan success status")
    scan_id: str = Field(..., description="Scan identifier")
    message: str = Field(..., description="Response message")
    results: Optional[ScanResult] = Field(None, description="Scan results")

# Enums
class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ScanStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class ExportStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class ExportType(str, Enum):
    SCANS = "scans"
    REPORTS = "reports"
    ALL = "all"

class ExportFormat(str, Enum):
    JSON = "json"
    CSV = "csv"
