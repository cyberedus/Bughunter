import os
import uuid
import logging
import aiohttp
import json
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class GPT4VulnerabilityAnalyzer:
    """
    Enterprise-grade GPT-4 service for vulnerability analysis and intelligence.
    Designed for maximum accuracy with minimal false positives.
    """
    
    def __init__(self):
        self.api_key = os.environ.get('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")
        
        # Check if this is an OpenRouter key
        self.is_openrouter = self.api_key.startswith('sk-or-v1-')
        
        # Set appropriate endpoints
        if self.is_openrouter:
            self.api_base = "https://openrouter.ai/api/v1"
            self.model = "openai/gpt-4"
        else:
            self.api_base = "https://api.openai.com/v1"
            self.model = "gpt-4"
            
        self.vulnerability_analysis_system_prompt = """
You are an elite cybersecurity expert and vulnerability researcher with 15+ years of experience in bug bounty hunting, penetration testing, and zero-day discovery. Your expertise includes:

- Deep knowledge of OWASP Top 10 and beyond
- Advanced web application security testing
- Network and infrastructure vulnerability assessment  
- Static code analysis for security flaws
- Zero-day vulnerability research and exploitation
- Enterprise-grade security consulting

Your mission is to provide 100% accurate vulnerability analysis with ZERO false positives. Every finding you report must be a genuine security vulnerability that could be exploited in real-world scenarios.

Key principles:
1. ACCURACY OVER QUANTITY - Only report verified vulnerabilities
2. DETAILED ANALYSIS - Provide comprehensive technical details
3. EXPLOIT FEASIBILITY - Explain how vulnerabilities can be exploited
4. RISK PRIORITIZATION - Clearly indicate severity and business impact
5. ACTIONABLE REMEDIATION - Provide specific fix recommendations

When analyzing vulnerabilities:
- Verify exploitability before reporting
- Consider business context and realistic attack scenarios
- Distinguish between theoretical and practical vulnerabilities
- Provide evidence and proof-of-concept where applicable
- Rate severity using CVSS 3.1 scoring methodology
"""

        self.payload_generation_system_prompt = """
You are an expert payload engineer specializing in creating custom exploits for vulnerability research and bug bounty hunting. Your role is to generate highly effective, targeted payloads for verified vulnerabilities.

Expertise areas:
- XSS payload crafting (DOM, Reflected, Stored)
- SQL injection payloads (Union, Blind, Time-based, Error-based)
- CSRF proof-of-concepts
- Command injection vectors
- File upload bypass techniques
- Authentication bypass methods
- SSRF exploitation payloads
- Directory traversal vectors

Payload generation principles:
1. SURGICAL PRECISION - Payloads must be specific to the target vulnerability
2. EVASION TECHNIQUES - Incorporate WAF and filter bypass methods
3. MINIMAL FOOTPRINT - Generate efficient, non-destructive payloads
4. PROOF-OF-CONCEPT - Focus on demonstrating impact, not causing damage
5. DOCUMENTATION - Explain payload components and expected behavior

Always provide:
- Multiple payload variations for different scenarios
- Explanation of payload mechanics
- Expected response indicators
- Potential detection signatures to avoid
"""

    async def make_gpt_request(self, messages: List[Dict[str, Any]], session_id: str) -> str:
        """Make a direct API request to GPT-4 via OpenRouter or OpenAI."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        if self.is_openrouter:
            headers["HTTP-Referer"] = "https://vulnscan-enterprise.com"
            headers["X-Title"] = "VulnScan Enterprise"
        
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": 4096,
            "temperature": 0.1,  # Low temperature for consistent, accurate results
            "top_p": 0.9
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_base}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result["choices"][0]["message"]["content"]
                    else:
                        error_text = await response.text()
                        logger.error(f"GPT-4 API error {response.status}: {error_text}")
                        raise Exception(f"API request failed with status {response.status}: {error_text}")
                        
        except Exception as e:
            logger.error(f"GPT-4 API request failed: {str(e)}")
            raise

    async def analyze_vulnerability(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a vulnerability with GPT-4 intelligence.
        
        Args:
            vulnerability_data: Dictionary containing:
                - type: Vulnerability type (e.g., "XSS", "SQLi", "CSRF")
                - details: Technical details of the vulnerability
                - context: Application context and environment
                - evidence: Proof or indicators of the vulnerability
                
        Returns:
            Dictionary containing GPT-4 analysis with confidence scores
        """
        try:
            session_id = f"vuln_scan_{uuid.uuid4().hex[:8]}"
            
            analysis_prompt = f"""
Analyze the following potential vulnerability and provide a comprehensive assessment:

VULNERABILITY TYPE: {vulnerability_data.get('type', 'Unknown')}

TECHNICAL DETAILS:
{vulnerability_data.get('details', '')}

APPLICATION CONTEXT:
{vulnerability_data.get('context', '')}

EVIDENCE/INDICATORS:
{vulnerability_data.get('evidence', '')}

Please provide:
1. VULNERABILITY VERIFICATION (Is this a genuine security vulnerability?)
2. EXPLOITABILITY ASSESSMENT (Can this be realistically exploited?)
3. SEVERITY RATING (Critical/High/Medium/Low with CVSS score)
4. ATTACK SCENARIOS (How could an attacker exploit this?)
5. BUSINESS IMPACT (What's the real-world impact?)
6. REMEDIATION STEPS (Specific technical fixes)
7. CONFIDENCE LEVEL (Your confidence in this assessment, 0-100%)

Focus on accuracy and avoid false positives. If uncertain, clearly state limitations.
"""

            messages = [
                {"role": "system", "content": self.vulnerability_analysis_system_prompt},
                {"role": "user", "content": analysis_prompt}
            ]
            
            response = await self.make_gpt_request(messages, session_id)
            
            # Parse and structure the response
            return {
                "gpt4_analysis": response,
                "session_id": session_id,
                "model_used": self.model,
                "analysis_type": "vulnerability_assessment",
                "api_provider": "openrouter" if self.is_openrouter else "openai"
            }
            
        except Exception as e:
            logger.error(f"GPT-4 vulnerability analysis failed: {str(e)}")
            raise

    async def generate_payload(self, vulnerability_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate custom exploit payloads using GPT-4.
        
        Args:
            vulnerability_info: Dictionary containing vulnerability details
            
        Returns:
            Dictionary containing generated payloads and explanations
        """
        try:
            session_id = f"payload_gen_{uuid.uuid4().hex[:8]}"
            
            payload_prompt = f"""
Generate custom exploit payloads for the following confirmed vulnerability:

VULNERABILITY TYPE: {vulnerability_info.get('type', '')}
TARGET DETAILS: {vulnerability_info.get('target', '')}
VULNERABILITY SPECIFICS: {vulnerability_info.get('specifics', '')}
CONSTRAINTS: {vulnerability_info.get('constraints', '')}

Requirements:
1. Generate 3-5 payload variations for different scenarios
2. Include WAF bypass techniques where applicable
3. Ensure payloads are safe for testing (proof-of-concept only)
4. Explain each payload's mechanism
5. Provide expected indicators of success

Focus on effectiveness while maintaining ethical testing standards.
"""

            messages = [
                {"role": "system", "content": self.payload_generation_system_prompt},
                {"role": "user", "content": payload_prompt}
            ]
            
            response = await self.make_gpt_request(messages, session_id)
            
            return {
                "generated_payloads": response,
                "session_id": session_id,
                "model_used": self.model,
                "generation_type": "exploit_payloads",
                "api_provider": "openrouter" if self.is_openrouter else "openai"
            }
            
        except Exception as e:
            logger.error(f"GPT-4 payload generation failed: {str(e)}")
            raise

    async def risk_assessment(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Perform intelligent risk assessment of multiple vulnerabilities.
        
        Args:
            scan_results: List of vulnerability findings
            
        Returns:
            Dictionary containing risk analysis and prioritization
        """
        try:
            session_id = f"risk_assess_{uuid.uuid4().hex[:8]}"
            
            # Prepare vulnerability summary
            vuln_summary = []
            for idx, vuln in enumerate(scan_results, 1):
                vuln_summary.append(f"""
VULNERABILITY #{idx}:
Type: {vuln.get('type', 'Unknown')}
Severity: {vuln.get('severity', 'Unknown')}
Location: {vuln.get('location', 'Unknown')}
Description: {vuln.get('description', 'No description')}
""")
            
            risk_prompt = f"""
Perform a comprehensive risk assessment for the following vulnerability findings:

{chr(10).join(vuln_summary)}

Provide:
1. OVERALL RISK RATING (Critical/High/Medium/Low)
2. ATTACK CHAIN ANALYSIS (How vulnerabilities could be chained)
3. PRIORITY RANKING (Which vulnerabilities to fix first)
4. BUSINESS IMPACT ASSESSMENT (Financial and operational risks)
5. COMPLIANCE IMPLICATIONS (Regulatory concerns)
6. STRATEGIC RECOMMENDATIONS (Long-term security improvements)

Consider real-world exploitation scenarios and business context.
"""

            messages = [
                {"role": "system", "content": self.vulnerability_analysis_system_prompt},
                {"role": "user", "content": risk_prompt}
            ]
            
            response = await self.make_gpt_request(messages, session_id)
            
            return {
                "risk_analysis": response,
                "session_id": session_id,
                "model_used": self.model,
                "assessment_type": "comprehensive_risk",
                "vulnerabilities_analyzed": len(scan_results),
                "api_provider": "openrouter" if self.is_openrouter else "openai"
            }
            
        except Exception as e:
            logger.error(f"GPT-4 risk assessment failed: {str(e)}")
            raise

    async def false_positive_filter(self, potential_finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use GPT-4 to filter out false positives with high accuracy.
        
        Args:
            potential_finding: Dictionary containing potential vulnerability
            
        Returns:
            Dictionary with validation results and confidence scores
        """
        try:
            session_id = f"fp_filter_{uuid.uuid4().hex[:8]}"
            
            validation_prompt = f"""
CRITICAL TASK: False Positive Detection

Evaluate if the following finding is a genuine security vulnerability or a false positive:

FINDING TYPE: {potential_finding.get('type', '')}
SCANNER OUTPUT: {potential_finding.get('scanner_output', '')}
RESPONSE DATA: {potential_finding.get('response_data', '')}
CONTEXT: {potential_finding.get('context', '')}

Your analysis must be extremely rigorous. Consider:
1. Could this be exploited by a real attacker?
2. Does the evidence definitively prove a vulnerability?
3. Are there alternative explanations for the observed behavior?
4. What level of access/conditions would exploitation require?

Provide:
- VERDICT: GENUINE_VULNERABILITY or FALSE_POSITIVE
- CONFIDENCE: Percentage (0-100%)
- REASONING: Detailed technical justification
- NEXT_STEPS: Recommended actions

Remember: False positives waste valuable time for bug hunters and security teams. Be absolutely certain.
"""

            messages = [
                {"role": "system", "content": self.vulnerability_analysis_system_prompt},
                {"role": "user", "content": validation_prompt}
            ]
            
            response = await self.make_gpt_request(messages, session_id)
            
            return {
                "validation_result": response,
                "session_id": session_id,
                "model_used": self.model,
                "validation_type": "false_positive_filter",
                "api_provider": "openrouter" if self.is_openrouter else "openai"
            }
            
        except Exception as e:
            logger.error(f"GPT-4 false positive filtering failed: {str(e)}")
            raise