from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Literal
from datetime import datetime
import uuid

# Enums for vulnerability types and severities
VulnerabilityType = Literal[
    "XSS", "SQLi", "CSRF", "SSRF", "Command_Injection", "File_Upload",
    "Directory_Traversal", "Authentication_Bypass", "Authorization_Flaw",
    "Information_Disclosure", "Insecure_Direct_Object_Reference",
    "Security_Misconfiguration", "Sensitive_Data_Exposure",
    "Insufficient_Logging", "Broken_Access_Control", "Code_Injection",
    "LDAP_Injection", "XML_Injection", "XXE", "Insecure_Deserialization",
    "Business_Logic_Flaw", "Race_Condition", "Buffer_Overflow",
    "Network_Vulnerability", "SSL_TLS_Issue", "Weak_Cryptography",
    "Session_Management", "Input_Validation", "Output_Encoding"
]

SeverityLevel = Literal["Critical", "High", "Medium", "Low", "Info"]
ScanStatus = Literal["Pending", "Running", "Completed", "Failed", "Cancelled"]
ScanType = Literal["Web_Application", "Network_Infrastructure", "Static_Code_Analysis", "Comprehensive"]

class ScanTarget(BaseModel):
    """Model for scan target configuration."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: ScanType
    target_url: Optional[str] = None  # For web app scans
    network_range: Optional[str] = None  # For network scans
    code_repository: Optional[str] = None  # For code analysis
    uploaded_files: Optional[List[str]] = None  # For file analysis
    custom_headers: Optional[Dict[str, str]] = {}
    authentication: Optional[Dict[str, Any]] = None
    scan_depth: Literal["Surface", "Standard", "Deep"] = "Standard"
    excluded_paths: Optional[List[str]] = []
    rate_limit: int = 10  # Requests per second
    timeout: int = 30  # Request timeout in seconds
    user_agent: str = "VulnScanner-Enterprise/1.0"
    created_at: datetime = Field(default_factory=datetime.utcnow)

class VulnerabilityEvidence(BaseModel):
    """Model for vulnerability evidence and proof."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_data: Optional[str] = None
    response_data: Optional[str] = None
    payload_used: Optional[str] = None
    response_time: Optional[float] = None
    status_code: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = {}
    response_body_snippet: Optional[str] = None
    screenshot_base64: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = {}

class Vulnerability(BaseModel):
    """Model for detected vulnerabilities."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    type: VulnerabilityType
    severity: SeverityLevel
    title: str
    description: str
    location: str  # URL, file path, or network location
    parameter: Optional[str] = None  # Vulnerable parameter
    method: Optional[str] = None  # HTTP method for web vulns
    
    # Technical details
    evidence: VulnerabilityEvidence
    cwe_id: Optional[str] = None  # Common Weakness Enumeration
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    
    # GPT-4 Analysis
    gpt4_analysis: Optional[str] = None
    gpt4_confidence: Optional[float] = None
    gpt4_session_id: Optional[str] = None
    is_false_positive: bool = False
    false_positive_reason: Optional[str] = None
    
    # Exploitation details
    exploitability: Literal["Easy", "Medium", "Hard", "Theoretical"] = "Medium"
    attack_complexity: Literal["Low", "Medium", "High"] = "Medium"
    privileges_required: Literal["None", "Low", "High"] = "None"
    user_interaction: Literal["None", "Required"] = "None"
    
    # Business impact
    confidentiality_impact: Literal["None", "Low", "High"] = "None"
    integrity_impact: Literal["None", "Low", "High"] = "None"
    availability_impact: Literal["None", "Low", "High"] = "None"
    
    # Remediation
    remediation_effort: Literal["Low", "Medium", "High"] = "Medium"
    remediation_steps: Optional[List[str]] = []
    references: Optional[List[str]] = []
    
    # Metadata
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    verified_at: Optional[datetime] = None
    fixed_at: Optional[datetime] = None
    scanner_module: str  # Which scanner detected this
    tags: Optional[List[str]] = []

class ScanConfiguration(BaseModel):
    """Model for scan configuration and settings."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    enabled_modules: List[str] = [
        "xss_scanner", "sql_injection", "csrf_detector", "file_upload_tester",
        "directory_traversal", "command_injection", "network_scanner", "ssl_analyzer"
    ]
    custom_payloads: Optional[Dict[str, List[str]]] = {}
    wordlists: Optional[Dict[str, str]] = {}  # Category -> file path
    advanced_options: Optional[Dict[str, Any]] = {}
    gpt4_analysis_enabled: bool = True
    false_positive_filtering: bool = True
    auto_verification: bool = True
    max_scan_time: int = 3600  # Maximum scan time in seconds
    parallel_threads: int = 10
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ScanJob(BaseModel):
    """Model for vulnerability scan jobs."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    target: ScanTarget
    configuration: ScanConfiguration
    
    # Status and progress
    status: ScanStatus = "Pending"
    progress_percentage: float = 0.0
    current_phase: Optional[str] = None
    
    # Results
    vulnerabilities_found: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    info_vulnerabilities: int = 0
    false_positives_filtered: int = 0
    
    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    
    # GPT-4 usage
    gpt4_analyses_performed: int = 0
    gpt4_tokens_used: int = 0
    
    # Error handling
    error_message: Optional[str] = None
    warnings: Optional[List[str]] = []
    
    # Metadata
    created_by: Optional[str] = None  # User ID
    created_at: datetime = Field(default_factory=datetime.utcnow)
    tags: Optional[List[str]] = []

class ScanStatistics(BaseModel):
    """Model for scan statistics and metrics."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    
    # Request statistics
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    timeout_requests: int = 0
    
    # Response statistics
    response_codes: Dict[int, int] = {}  # Status code -> count
    average_response_time: float = 0.0
    max_response_time: float = 0.0
    min_response_time: float = 0.0
    
    # Coverage statistics
    endpoints_discovered: int = 0
    parameters_tested: int = 0
    forms_analyzed: int = 0
    files_scanned: int = 0
    
    # Performance metrics
    requests_per_second: float = 0.0
    data_transferred_mb: float = 0.0
    scanner_efficiency: float = 0.0  # Vulnerabilities per 1000 requests
    
    # GPT-4 metrics
    gpt4_accuracy_rate: float = 0.0
    false_positive_rate: float = 0.0
    verification_success_rate: float = 0.0
    
    created_at: datetime = Field(default_factory=datetime.utcnow)

class GPTAnalysisResult(BaseModel):
    """Model for GPT-4 analysis results."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vulnerability_id: str
    scan_id: str
    session_id: str
    
    # Analysis details
    analysis_type: Literal[
        "vulnerability_assessment", "exploit_payloads", 
        "comprehensive_risk", "false_positive_filter"
    ]
    model_used: str = "gpt-4.1"
    analysis_prompt: str
    analysis_response: str
    
    # Confidence and validation
    confidence_score: Optional[float] = None
    validation_result: Optional[str] = None
    
    # Usage metrics
    tokens_used: int = 0
    processing_time_seconds: float = 0.0
    
    # Results
    generated_payloads: Optional[List[str]] = []
    risk_assessment: Optional[Dict[str, Any]] = {}
    remediation_recommendations: Optional[List[str]] = []
    
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ScanReport(BaseModel):
    """Model for comprehensive scan reports."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    scan_name: str
    target_info: Dict[str, Any]
    
    # Executive summary
    executive_summary: str
    overall_risk_rating: SeverityLevel
    total_vulnerabilities: int
    critical_issues: int
    
    # Detailed findings
    vulnerability_breakdown: Dict[SeverityLevel, int]
    top_vulnerabilities: List[str]  # Vulnerability IDs
    attack_vectors: List[str]
    compliance_status: Optional[Dict[str, bool]] = {}
    
    # Recommendations
    immediate_actions: List[str]
    strategic_recommendations: List[str]
    remediation_timeline: Optional[Dict[str, str]] = {}
    
    # Technical appendix
    scan_methodology: str
    tools_used: List[str]
    false_positive_analysis: str
    gpt4_analysis_summary: str
    
    # Metadata
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    report_version: str = "1.0"
    generated_by: str = "VulnScanner-Enterprise"