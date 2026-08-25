# -*- coding: utf-8 -*-
"""
Regional ICT Data Leak Prevention (DLP) Dashboard
Custom Tailored for: DOT Ethiopia (Corporate Security Framework)
"""
import re
import json

class DotEthiopiaDLPEngine:
    def __init__(self):
        self.regional_office = "Addis Ababa Headquarters"
        # Structural signatures to discover unauthorized data sharing
        self.dlp_signatures = {
            "confidential_marker": r"(?i)(internal use only|confidential|salary|passport)",
            "ethiopian_phone": r"(\+251|^09)\d{8}"
        }

    def audit_email_stream(self, sender, recipient, email_body):
        """Scans corporate communications for critical text exposures."""
        triggered_rules = []
        
        for rule, pattern in self.dlp_signatures.items():
            if re.search(pattern, email_body):
                triggered_rules.append(rule)
                
        risk_level = "Low"
        if len(triggered_rules) >= 2:
            risk_level = "Critical"
        elif len(triggered_rules) == 1:
            risk_level = "Medium"

        return {
            "audit_type": "Email_Management_Audit",
            "sender_id": sender,
            "recipient_id": recipient,
            "violations_detected": triggered_rules,
            "action_required": "Quarantine Message" if risk_level == "Critical" else "Log Transaction",
            "risk_assessment": risk_level
        }

    def audit_hr_document(self, document_title, file_content):
        """Evaluates personal HR documents for compliance and access controls."""
        is_exposed = "Strictly Confidential" in file_content or "Salary Certificate" in document_title
        
        return {
            "audit_type": "Personal_HR_Document_Audit",
            "document_name": document_title,
            "integrity_status": "Flagged for Isolation" if is_exposed else "Compliant",
            "encryption_recommendation": "AES-256 Hardening Required" if is_exposed else "Standard Protection"
        }

if __name__ == "__main__":
    print("=" * 60)
    print("DOT Ethiopia Regional ICT Security System Active")
    print("=" * 60)
    
    dlp = DotEthiopiaDLPEngine()

    # 1. Test Outbound Corporate Email Monitor
    email_sample = "Hello team, here is the confidential document with my phone +251911234567"
    email_result = dlp.audit_email_stream("employee@dotethiopia.org", "external@gmail.com", email_sample)
    print("\n[Email Audit Output]:")
    print(json.dumps(email_result, indent=4))

    # 2. Test Personal HR File Inspector
    hr_result = dlp.audit_hr_document("Salary Certificate_2026.docx", "Contains sensitive private compensation figures.")
    print("\n[HR Document Audit Output]:")
    print(json.dumps(hr_result, indent=4))
