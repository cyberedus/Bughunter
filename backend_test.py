#!/usr/bin/env python3
"""
Enterprise Vulnerability Scanner Backend API Tests
Testing all critical endpoints for GPT-4 integration and scan management.
"""

import asyncio
import aiohttp
import json
import os
import sys
from datetime import datetime
from typing import Dict, Any

# Get backend URL from frontend .env file
def get_backend_url():
    try:
        with open('/app/frontend/.env', 'r') as f:
            for line in f:
                if line.startswith('REACT_APP_BACKEND_URL='):
                    return line.split('=', 1)[1].strip()
    except Exception as e:
        print(f"Error reading frontend .env: {e}")
        return None

BACKEND_URL = get_backend_url()
if not BACKEND_URL:
    print("ERROR: Could not get REACT_APP_BACKEND_URL from frontend/.env")
    sys.exit(1)

API_BASE = f"{BACKEND_URL}/api"
print(f"Testing backend API at: {API_BASE}")

class BackendTester:
    def __init__(self):
        self.session = None
        self.test_results = []
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60),
            headers={'Content-Type': 'application/json'}
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def log_test(self, test_name: str, success: bool, details: str = "", response_data: Any = None):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"    Details: {details}")
        if response_data and not success:
            print(f"    Response: {response_data}")
        
        self.test_results.append({
            'test': test_name,
            'success': success,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    async def test_basic_api_health(self):
        """Test basic API health endpoints"""
        print("\n=== TESTING BASIC API HEALTH ===")
        
        # Test root endpoint
        try:
            async with self.session.get(f"{API_BASE}/") as response:
                if response.status == 200:
                    data = await response.json()
                    expected_features = [
                        "Web Application Security Testing",
                        "Network Infrastructure Scanning", 
                        "Static Code Analysis",
                        "GPT-4 Intelligent Analysis"
                    ]
                    
                    features = data.get('features', [])
                    has_required_features = all(feature in features for feature in expected_features)
                    
                    if has_required_features and data.get('status') == 'operational':
                        self.log_test("GET /api/ - Scanner info", True, f"Status: {data.get('status')}, Features: {len(features)}")
                    else:
                        self.log_test("GET /api/ - Scanner info", False, f"Missing features or wrong status", data)
                else:
                    self.log_test("GET /api/ - Scanner info", False, f"HTTP {response.status}", await response.text())
        except Exception as e:
            self.log_test("GET /api/ - Scanner info", False, f"Exception: {str(e)}")
    
    async def test_gpt4_integration(self):
        """Test GPT-4 integration endpoints (MOST IMPORTANT)"""
        print("\n=== TESTING GPT-4 INTEGRATION ===")
        
        # Test GPT-4 connection
        try:
            async with self.session.post(f"{API_BASE}/gpt4/test-connection") as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('success') and data.get('session_id'):
                        self.log_test("POST /api/gpt4/test-connection", True, f"Model: {data.get('model', 'unknown')}")
                    else:
                        self.log_test("POST /api/gpt4/test-connection", False, "Missing success or session_id", data)
                else:
                    error_text = await response.text()
                    self.log_test("POST /api/gpt4/test-connection", False, f"HTTP {response.status}", error_text)
        except Exception as e:
            self.log_test("POST /api/gpt4/test-connection", False, f"Exception: {str(e)}")
        
        # Test vulnerability analysis
        try:
            analysis_request = {
                "type": "XSS",
                "details": "Reflected XSS vulnerability in search parameter",
                "context": "E-commerce web application with user input validation",
                "evidence": "Parameter 'q' reflects user input without encoding in search results page"
            }
            
            async with self.session.post(
                f"{API_BASE}/gpt4/analyze-vulnerability",
                json=analysis_request
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('success') and data.get('gpt4_analysis') and data.get('analysis_id'):
                        self.log_test("POST /api/gpt4/analyze-vulnerability", True, f"Analysis ID: {data.get('analysis_id')}")
                    else:
                        self.log_test("POST /api/gpt4/analyze-vulnerability", False, "Missing required fields", data)
                else:
                    error_text = await response.text()
                    self.log_test("POST /api/gpt4/analyze-vulnerability", False, f"HTTP {response.status}", error_text)
        except Exception as e:
            self.log_test("POST /api/gpt4/analyze-vulnerability", False, f"Exception: {str(e)}")
        
        # Test payload generation
        try:
            payload_request = {
                "type": "XSS",
                "target": "https://example.com/search?q=",
                "specifics": "Reflected XSS in search parameter, basic HTML encoding present",
                "constraints": "Must bypass basic HTML encoding, avoid common XSS filters"
            }
            
            async with self.session.post(
                f"{API_BASE}/gpt4/generate-payload",
                json=payload_request
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('success') and data.get('generated_payloads') and data.get('generation_id'):
                        self.log_test("POST /api/gpt4/generate-payload", True, f"Generation ID: {data.get('generation_id')}")
                    else:
                        self.log_test("POST /api/gpt4/generate-payload", False, "Missing required fields", data)
                else:
                    error_text = await response.text()
                    self.log_test("POST /api/gpt4/generate-payload", False, f"HTTP {response.status}", error_text)
        except Exception as e:
            self.log_test("POST /api/gpt4/generate-payload", False, f"Exception: {str(e)}")
    
    async def test_scan_management(self):
        """Test scan creation and management workflow"""
        print("\n=== TESTING SCAN MANAGEMENT ===")
        
        scan_id = None
        
        # Test scan creation
        try:
            scan_request = {
                "name": "Test Web Application Scan",
                "description": "Comprehensive security test of web application",
                "scan_type": "Web_Application",
                "target_url": "https://example.com",
                "scan_depth": "Standard",
                "gpt4_analysis_enabled": True
            }
            
            async with self.session.post(
                f"{API_BASE}/scan/create",
                json=scan_request
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('success') and data.get('scan_id'):
                        scan_id = data.get('scan_id')
                        self.log_test("POST /api/scan/create", True, f"Scan ID: {scan_id}")
                    else:
                        self.log_test("POST /api/scan/create", False, "Missing success or scan_id", data)
                else:
                    error_text = await response.text()
                    self.log_test("POST /api/scan/create", False, f"HTTP {response.status}", error_text)
        except Exception as e:
            self.log_test("POST /api/scan/create", False, f"Exception: {str(e)}")
        
        # Test scan status retrieval (if scan was created)
        if scan_id:
            try:
                async with self.session.get(f"{API_BASE}/scan/{scan_id}/status") as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('scan_id') == scan_id and 'status' in data:
                            self.log_test("GET /api/scan/{scan_id}/status", True, f"Status: {data.get('status')}")
                        else:
                            self.log_test("GET /api/scan/{scan_id}/status", False, "Invalid response format", data)
                    else:
                        error_text = await response.text()
                        self.log_test("GET /api/scan/{scan_id}/status", False, f"HTTP {response.status}", error_text)
            except Exception as e:
                self.log_test("GET /api/scan/{scan_id}/status", False, f"Exception: {str(e)}")
            
            # Test scan results retrieval
            try:
                async with self.session.get(f"{API_BASE}/scan/{scan_id}/results") as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('scan_id') == scan_id and 'total_vulnerabilities' in data:
                            self.log_test("GET /api/scan/{scan_id}/results", True, f"Vulnerabilities: {data.get('total_vulnerabilities')}")
                        else:
                            self.log_test("GET /api/scan/{scan_id}/results", False, "Invalid response format", data)
                    else:
                        error_text = await response.text()
                        self.log_test("GET /api/scan/{scan_id}/results", False, f"HTTP {response.status}", error_text)
            except Exception as e:
                self.log_test("GET /api/scan/{scan_id}/results", False, f"Exception: {str(e)}")
        else:
            self.log_test("GET /api/scan/{scan_id}/status", False, "Skipped - no scan_id from creation")
            self.log_test("GET /api/scan/{scan_id}/results", False, "Skipped - no scan_id from creation")
    
    async def test_legacy_endpoints(self):
        """Test legacy status endpoints for compatibility"""
        print("\n=== TESTING LEGACY ENDPOINTS ===")
        
        # Test status creation
        try:
            status_request = {
                "client_name": "VulnScanner Test Client"
            }
            
            async with self.session.post(
                f"{API_BASE}/status",
                json=status_request
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('id') and data.get('client_name') == status_request['client_name']:
                        self.log_test("POST /api/status", True, f"Status ID: {data.get('id')}")
                    else:
                        self.log_test("POST /api/status", False, "Invalid response format", data)
                else:
                    error_text = await response.text()
                    self.log_test("POST /api/status", False, f"HTTP {response.status}", error_text)
        except Exception as e:
            self.log_test("POST /api/status", False, f"Exception: {str(e)}")
        
        # Test status retrieval
        try:
            async with self.session.get(f"{API_BASE}/status") as response:
                if response.status == 200:
                    data = await response.json()
                    if isinstance(data, list):
                        self.log_test("GET /api/status", True, f"Status checks: {len(data)}")
                    else:
                        self.log_test("GET /api/status", False, "Response not a list", data)
                else:
                    error_text = await response.text()
                    self.log_test("GET /api/status", False, f"HTTP {response.status}", error_text)
        except Exception as e:
            self.log_test("GET /api/status", False, f"Exception: {str(e)}")
    
    async def test_error_handling(self):
        """Test error handling for invalid requests"""
        print("\n=== TESTING ERROR HANDLING ===")
        
        # Test invalid scan creation
        try:
            invalid_request = {
                "name": "",  # Empty name should fail
                "scan_type": "Invalid_Type"  # Invalid scan type
            }
            
            async with self.session.post(
                f"{API_BASE}/scan/create",
                json=invalid_request
            ) as response:
                if response.status >= 400:
                    self.log_test("POST /api/scan/create (invalid)", True, f"Correctly rejected with HTTP {response.status}")
                else:
                    data = await response.json()
                    self.log_test("POST /api/scan/create (invalid)", False, "Should have rejected invalid request", data)
        except Exception as e:
            self.log_test("POST /api/scan/create (invalid)", False, f"Exception: {str(e)}")
        
        # Test non-existent scan status
        try:
            fake_scan_id = "non-existent-scan-id"
            async with self.session.get(f"{API_BASE}/scan/{fake_scan_id}/status") as response:
                if response.status == 404:
                    self.log_test("GET /api/scan/{fake_id}/status", True, "Correctly returned 404 for non-existent scan")
                else:
                    data = await response.text()
                    self.log_test("GET /api/scan/{fake_id}/status", False, f"Should return 404, got {response.status}", data)
        except Exception as e:
            self.log_test("GET /api/scan/{fake_id}/status", False, f"Exception: {str(e)}")
    
    async def run_all_tests(self):
        """Run all backend tests"""
        print(f"🚀 Starting Enterprise Vulnerability Scanner Backend Tests")
        print(f"📡 Backend URL: {API_BASE}")
        print(f"⏰ Test started at: {datetime.utcnow().isoformat()}")
        
        await self.test_basic_api_health()
        await self.test_gpt4_integration()
        await self.test_scan_management()
        await self.test_legacy_endpoints()
        await self.test_error_handling()
        
        # Summary
        print("\n" + "="*60)
        print("📊 TEST SUMMARY")
        print("="*60)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print("\n🔍 FAILED TESTS:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  ❌ {result['test']}: {result['details']}")
        
        print(f"\n⏰ Test completed at: {datetime.utcnow().isoformat()}")
        
        return passed_tests, failed_tests

async def main():
    """Main test runner"""
    async with BackendTester() as tester:
        passed, failed = await tester.run_all_tests()
        
        # Exit with appropriate code
        if failed > 0:
            print(f"\n⚠️  {failed} tests failed. Check the output above for details.")
            sys.exit(1)
        else:
            print(f"\n🎉 All {passed} tests passed successfully!")
            sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())