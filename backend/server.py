from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import uuid
from datetime import datetime

# Import our models and services
from models.scanner_models import (
    ScanJob, ScanTarget, ScanConfiguration, Vulnerability, ScanStatus,
    VulnerabilityType, SeverityLevel, ScanType
)
from services.gpt4_service import GPT4VulnerabilityAnalyzer

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Initialize GPT-4 service
gpt4_service = GPT4VulnerabilityAnalyzer()

# Create the main app without a prefix
app = FastAPI(title="Enterprise Vulnerability Scanner API", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Define request/response models
class VulnerabilityAnalysisRequest(BaseModel):
    type: str
    details: str
    context: str
    evidence: str

class PayloadGenerationRequest(BaseModel):
    type: str
    target: str
    specifics: str
    constraints: str = ""

class ScanCreateRequest(BaseModel):
    name: str
    description: str = ""
    scan_type: ScanType
    target_url: str = None
    network_range: str = None
    code_repository: str = None
    scan_depth: str = "Standard"
    gpt4_analysis_enabled: bool = True

# Legacy routes for compatibility
class StatusCheck(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class StatusCheckCreate(BaseModel):
    client_name: str

@api_router.get("/")
async def root():
    return {
        "message": "Enterprise Vulnerability Scanner API v1.0",
        "status": "operational",
        "features": [
            "Web Application Security Testing",
            "Network Infrastructure Scanning", 
            "Static Code Analysis",
            "GPT-4 Intelligent Analysis",
            "False Positive Filtering",
            "Custom Payload Generation"
        ]
    }

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.dict()
    status_obj = StatusCheck(**status_dict)
    _ = await db.status_checks.insert_one(status_obj.dict())
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    status_checks = await db.status_checks.find().to_list(1000)
    return [StatusCheck(**status_check) for status_check in status_checks]

# GPT-4 Intelligence Endpoints
@api_router.post("/gpt4/analyze-vulnerability")
async def analyze_vulnerability_with_gpt4(request: VulnerabilityAnalysisRequest):
    """
    Analyze a vulnerability using GPT-4 for maximum accuracy.
    """
    try:
        vulnerability_data = {
            "type": request.type,
            "details": request.details,
            "context": request.context,
            "evidence": request.evidence
        }
        
        result = await gpt4_service.analyze_vulnerability(vulnerability_data)
        
        # Store the analysis in database
        analysis_record = {
            "analysis_id": str(uuid.uuid4()),
            "vulnerability_data": vulnerability_data,
            "gpt4_result": result,
            "created_at": datetime.utcnow()
        }
        
        await db.gpt4_analyses.insert_one(analysis_record)
        
        return {
            "success": True,
            "analysis_id": analysis_record["analysis_id"],
            "gpt4_analysis": result["gpt4_analysis"],
            "session_id": result["session_id"]
        }
        
    except Exception as e:
        logging.error(f"GPT-4 vulnerability analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@api_router.post("/gpt4/generate-payload")
async def generate_payload_with_gpt4(request: PayloadGenerationRequest):
    """
    Generate custom exploit payloads using GPT-4.
    """
    try:
        vulnerability_info = {
            "type": request.type,
            "target": request.target,
            "specifics": request.specifics,
            "constraints": request.constraints
        }
        
        result = await gpt4_service.generate_payload(vulnerability_info)
        
        # Store the payload generation in database
        payload_record = {
            "generation_id": str(uuid.uuid4()),
            "vulnerability_info": vulnerability_info,
            "gpt4_result": result,
            "created_at": datetime.utcnow()
        }
        
        await db.gpt4_payloads.insert_one(payload_record)
        
        return {
            "success": True,
            "generation_id": payload_record["generation_id"],
            "generated_payloads": result["generated_payloads"],
            "session_id": result["session_id"]
        }
        
    except Exception as e:
        logging.error(f"GPT-4 payload generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Payload generation failed: {str(e)}")

@api_router.post("/gpt4/test-connection")
async def test_gpt4_connection():
    """
    Test GPT-4 connection and API key validity.
    """
    try:
        # Simple test analysis
        test_data = {
            "type": "XSS",
            "details": "Test connection to GPT-4 API",
            "context": "API connectivity test",
            "evidence": "Testing API key and service availability"
        }
        
        result = await gpt4_service.analyze_vulnerability(test_data)
        
        return {
            "success": True,
            "message": "GPT-4 connection successful",
            "model": result.get("model_used", "gpt-4.1"),
            "session_id": result.get("session_id"),
            "test_timestamp": datetime.utcnow()
        }
        
    except Exception as e:
        logging.error(f"GPT-4 connection test failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Connection test failed: {str(e)}")

# Scan Management Endpoints
@api_router.post("/scan/create", response_model=Dict[str, Any])
async def create_scan(request: ScanCreateRequest):
    """
    Create a new vulnerability scan job.
    """
    try:
        # Create scan target
        target = ScanTarget(
            type=request.scan_type,
            target_url=request.target_url,
            network_range=request.network_range,
            code_repository=request.code_repository,
            scan_depth=request.scan_depth
        )
        
        # Create scan configuration
        config = ScanConfiguration(
            gpt4_analysis_enabled=request.gpt4_analysis_enabled
        )
        
        # Create scan job
        scan = ScanJob(
            name=request.name,
            description=request.description,
            target=target,
            configuration=config
        )
        
        # Store in database
        scan_dict = scan.dict()
        await db.scan_jobs.insert_one(scan_dict)
        
        return {
            "success": True,
            "scan_id": scan.id,
            "message": "Scan job created successfully",
            "status": scan.status
        }
        
    except Exception as e:
        logging.error(f"Scan creation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create scan: {str(e)}")

@api_router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """
    Get current status of a scan job.
    """
    try:
        scan = await db.scan_jobs.find_one({"id": scan_id})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
            
        return {
            "scan_id": scan_id,
            "status": scan["status"],
            "progress": scan["progress_percentage"],
            "current_phase": scan.get("current_phase"),
            "vulnerabilities_found": scan["vulnerabilities_found"],
            "started_at": scan.get("started_at"),
            "estimated_completion": scan.get("estimated_completion")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to get scan status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Status retrieval failed: {str(e)}")

@api_router.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """
    Get results of a completed scan.
    """
    try:
        # Get scan job
        scan = await db.scan_jobs.find_one({"id": scan_id})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
            
        # Get vulnerabilities for this scan
        vulnerabilities = await db.vulnerabilities.find({"scan_id": scan_id}).to_list(1000)
        
        return {
            "scan_id": scan_id,
            "scan_status": scan["status"],
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "scan_summary": {
                "critical": scan["critical_vulnerabilities"],
                "high": scan["high_vulnerabilities"], 
                "medium": scan["medium_vulnerabilities"],
                "low": scan["low_vulnerabilities"],
                "info": scan["info_vulnerabilities"]
            },
            "gpt4_analyses": scan["gpt4_analyses_performed"],
            "false_positives_filtered": scan["false_positives_filtered"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to get scan results: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Results retrieval failed: {str(e)}")

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_event():
    logger.info("Enterprise Vulnerability Scanner API starting up...")
    logger.info(f"GPT-4 service configured with {'OpenRouter' if gpt4_service.is_openrouter else 'OpenAI'} API")
    logger.info("GPT-4 connection will be tested on first use to conserve API credits")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
    logger.info("Database connection closed")
