import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict


class SASTParser:
    SEVERITY_MAP = {0: "info", 1: "warning", 2: "error"}

    CWE_MAPPING = {
        "security/detect-eval-with-expression": "CWE-95",
        "security/detect-non-literal-require": "CWE-494",
        "security/detect-non-literal-regexp": "CWE-400",
        "security/detect-non-literal-fs-filename": "CWE-73",
        "security/detect-unsafe-regex": "CWE-1333",
        "security/detect-buffer-noassert": "CWE-703",
        "security/detect-child-process": "CWE-78",
        "security/detect-disable-mustache-escape": "CWE-79",
        "security/detect-no-csrf-before-method-override": "CWE-352",
        "security/detect-possible-timing-attacks": "CWE-208",
        "security/detect-pseudoRandomBytes": "CWE-338",
        "security/detect-object-injection": "CWE-94",
        "no-secrets/no-secrets": "CWE-798",
    }

    def __init__(self, report_dir: str = "."):
        self.report_dir = Path(report_dir)
        self.vulnerabilities: List[Dict] = []
        self.stats = {
            "total_files_scanned": 0,
            "files_with_issues": 0,
            "total_vulnerabilities": 0,
            "by_severity": defaultdict(int),
            "by_component": defaultdict(int),
            "by_type": defaultdict(int),
            "by_cwe": defaultdict(int),
            "by_owasp": defaultdict(int),
        }

    def parse_eslint_report(self, report_path: Path, component: str):
        """Parse ESLint JSON report"""
        if not report_path.exists():
            print(f"⚠️  Report not found: {report_path}")
            return

        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        print(f"\n📄 Parsing {component} report: {report_path.name}")

        for file_result in data:
            file_path = file_result.get("filePath", "")
            messages = file_result.get("messages", [])

            if not messages:
                continue

            self.stats["files_with_issues"] += 1

            for msg in messages:
                vuln = self._create_vulnerability(msg, file_path, component)
                self.vulnerabilities.append(vuln)

                # Update statistics
                self.stats["total_vulnerabilities"] += 1
                self.stats["by_severity"][vuln["severity"]] += 1
                self.stats["by_component"][component] += 1
                self.stats["by_type"][vuln["rule_id"]] += 1
                self.stats["by_cwe"][vuln["cwe"]] += 1
                self.stats["by_owasp"][vuln["owasp_category"]] += 1

        print(f"✓ Found {len([v for v in self.vulnerabilities if v['component'] == component])} vulnerabilities in {component}")

    def _create_vulnerability(self, msg: Dict, file_path: str, component: str) -> Dict:
        """Create normalized vulnerability object"""
        rule_id = msg.get("ruleId", "unknown")
        severity_code = msg.get("severity", 1)
        severity = self.SEVERITY_MAP.get(severity_code, "warning")

        # Determine vulnerability type
        if "no-secrets" in rule_id:
            vuln_type = "Hardcoded Secrets"
        elif "eval" in rule_id:
            vuln_type = "Code Injection"
        elif "object-injection" in rule_id:
            vuln_type = "Object Injection"
        elif "regexp" in rule_id:
            vuln_type = "ReDoS Vulnerability"
        else:
            vuln_type = rule_id.replace("security/detect-", "").replace("-", " ").title()

        # Map to CWE
        cwe = self.CWE_MAPPING.get(rule_id, "CWE-Unknown")

        # Calculate risk level
        risk_level = self._calculate_risk_level(severity, cwe)

        # Generate unique ID
        vuln_id = self._generate_vuln_id(file_path, msg.get("line", 0), rule_id)

        # Normalize file path
        normalized_path = file_path.replace("/home/runner/work/Deploiement_chronogaz_site3/Deploiement_chronogaz_site3/", "")

        return {
            "id": vuln_id,
            "source": "SAST",
            "tool": "ESLint-Security",
            "component": component,
            "rule_id": rule_id,
            "type": vuln_type,
            "severity": severity,
            "risk_level": risk_level,
            "message": msg.get("message", ""),
            "description": self._enrich_description(msg.get("message", ""), rule_id),
            "location": {
                "file": normalized_path,
                "line": msg.get("line", 0),
                "column": msg.get("column", 0),
                "end_line": msg.get("endLine", msg.get("line", 0)),
                "end_column": msg.get("endColumn", msg.get("column", 0)),
            },
            "cwe": cwe,
            "recommendation": self._get_recommendation(rule_id),
            "owasp_category": self._map_to_owasp(cwe),
            "nist_csf_function": self._map_to_nist_csf(cwe),
        }

    def _generate_vuln_id(self, file_path: str, line: int, rule_id: str) -> str:
        """Generate unique vulnerability ID"""
        import hashlib
        unique_string = f"{file_path}:{line}:{rule_id}"
        return f"SAST-{hashlib.md5(unique_string.encode()).hexdigest()[:8].upper()}"

    def _calculate_risk_level(self, severity: str, cwe: str) -> str:
        """Calculate risk level based on severity and CWE"""
        high_risk_cwes = ["CWE-95", "CWE-798", "CWE-94", "CWE-78"]

        if severity == "error" or cwe in high_risk_cwes:
            return "critical"
        elif severity == "warning" and cwe in ["CWE-79", "CWE-89", "CWE-352"]:
            return "high"
        elif severity == "warning":
            return "medium"
        else:
            return "low"

    def _enrich_description(self, message: str, rule_id: str) -> str:
        """Enrich vulnerability description"""
        descriptions = {
            "no-secrets/no-secrets": "Hardcoded secrets detected in source code. This can lead to unauthorized access if the code is exposed.",
            "security/detect-eval-with-expression": "Use of eval() with expressions can lead to arbitrary code execution.",
            "security/detect-object-injection": "Generic object injection can allow attackers to access or modify object properties.",
            "security/detect-non-literal-regexp": "Non-literal regular expressions can lead to ReDoS (Regular Expression Denial of Service) attacks.",
            "security/detect-child-process": "Unsafe use of child_process can lead to command injection vulnerabilities.",
        }

        base_desc = descriptions.get(rule_id, message)
        return f"{base_desc} | Original: {message}"

    def _get_recommendation(self, rule_id: str) -> str:
        """Get security recommendation"""
        recommendations = {
            "no-secrets/no-secrets": "Remove all hardcoded secrets from source code immediately.",
            "security/detect-eval-with-expression": "Avoid using eval(). Use safer alternatives like JSON.parse() or Function constructor with proper validation.",
            "security/detect-object-injection": "Validate and sanitize all object keys before using bracket notation.",
            "security/detect-non-literal-regexp": "Use literal regular expressions or validate input before creating RegExp objects.",
            "security/detect-child-process": "Validate and sanitize all inputs before passing to child_process functions.",
        }
        return recommendations.get(rule_id, "Review and validate the code for security issues.")

    def _map_to_owasp(self, cwe: str) -> str:
        """Map CWE to OWASP Top 10 2021"""
        owasp_map = {
            'CWE-798': 'A07:2021 - Identification and Authentication Failures',
            'CWE-95': 'A03:2021 - Injection',
            'CWE-94': 'A03:2021 - Injection',
            'CWE-78': 'A03:2021 - Injection',
            'CWE-79': 'A03:2021 - Injection',
            'CWE-400': 'A04:2021 - Insecure Design',
            'CWE-1333': 'A04:2021 - Insecure Design',
            'CWE-352': 'A01:2021 - Broken Access Control',
            'CWE-208': 'A02:2021 - Cryptographic Failures',
            'CWE-338': 'A02:2021 - Cryptographic Failures',
        }
        return owasp_map.get(cwe, 'N/A')

    def _map_to_nist_csf(self, cwe: str) -> str:
        """Map CWE to NIST CSF function"""
        nist_map = {
            'CWE-798': 'PR.AC - Access Control',
            'CWE-95': 'PR.IP - Protective Technology',
            'CWE-94': 'PR.DS - Data Security',
            'CWE-78': 'PR.IP - Protective Technology',
            'CWE-79': 'PR.DS - Data Security',
            'CWE-400': 'DE.CM - Security Continuous Monitoring',
            'CWE-1333': 'DE.CM - Security Continuous Monitoring',
            'CWE-352': 'PR.DS - Data Security',
            'CWE-208': 'PR.DS - Data Security',
            'CWE-338': 'PR.DS - Data Security',
        }
        return nist_map.get(cwe, 'PR.IP - Protective Technology')

    def _deduplicate_vulnerabilities(self):
        """Deduplicate vulnerabilities by (file, line, rule_id)"""
        seen = {}
        deduplicated = []
        duplicates_removed = 0

        for vuln in self.vulnerabilities:
            key = (
                vuln['location']['file'],
                vuln['location']['line'],
                vuln['rule_id']
            )

            if key not in seen:
                seen[key] = vuln
                deduplicated.append(vuln)
            else:
                duplicates_removed += 1
                # Merge column information if different
                existing = seen[key]
                if vuln['location']['column'] != existing['location']['column']:
                    existing['location']['column'] = min(
                        existing['location']['column'],
                        vuln['location']['column']
                    )
                    existing['location']['end_column'] = max(
                        existing['location']['end_column'],
                        vuln['location']['end_column']
                    )

        original_count = len(self.vulnerabilities)
        self.vulnerabilities = deduplicated
        self.stats["total_vulnerabilities"] = len(deduplicated)

        print(f"\n🔄 Déduplication des vulnérabilités...")
        print(f"   Avant : {original_count} vulnérabilités")
        print(f"   Après : {len(deduplicated)} vulnérabilités uniques")
        print(f"   Doublons éliminés : {duplicates_removed}")

    def _validate_deduplication(self) -> bool:
        """Validate that no duplicates remain"""
        seen_keys = set()
        duplicates = []

        for vuln in self.vulnerabilities:
            key = (
                vuln['location']['file'],
                vuln['location']['line'],
                vuln['rule_id']
            )
            if key in seen_keys:
                duplicates.append(key)
            seen_keys.add(key)

        if duplicates:
            print(f"⚠️ Doublons détectés après déduplication : {len(duplicates)}")
            for dup in duplicates[:5]:
                print(f"   - {dup}")
            return False

        print("✅ Aucun doublon détecté après déduplication")
        return True

    def parse_all_reports(self) -> Dict:
        """Parse all SAST reports"""
        print("=" * 70)
        print("🔍 SAST PARSER - Static Application Security Testing")
        print("=" * 70)

        client_report = self.report_dir / "sast-eslint-client.json"
        if client_report.exists():
            print(f"\n📄 Processing client report...")
            self.parse_eslint_report(client_report, "client")
            self.stats["total_files_scanned"] += self._count_files(client_report)

        api_report = self.report_dir / "sast-eslint-api.json"
        if api_report.exists():
            print(f"\n📄 Processing API report...")
            self.parse_eslint_report(api_report, "api")
            self.stats["total_files_scanned"] += self._count_files(api_report)

        # Deduplicate vulnerabilities
        if self.vulnerabilities:
            self._deduplicate_vulnerabilities()
            self._validate_deduplication()

        # Generate final report
        report = self._generate_report()

        print("\n" + "=" * 70)
        print("📊 SAST PARSING SUMMARY")
        print("=" * 70)
        print(f"Total files scanned: {self.stats['total_files_scanned']}")
        print(f"Files with issues: {self.stats['files_with_issues']}")
        print(f"Total vulnerabilities: {self.stats['total_vulnerabilities']}")
        print(f"Risk score: {report['summary']['risk_score']:.2f}/100")

        print("\nBy severity:")
        for sev, count in self.stats["by_severity"].items():
            print(f"  {sev}: {count}")

        print("\nBy component:")
        for comp, count in self.stats["by_component"].items():
            print(f"  {comp}: {count}")

        return report

    def _count_files(self, report_path: Path) -> int:
        """Count total files in report"""
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return len(data)

    def _generate_report(self) -> Dict:
        """Generate final unified report"""
        risk_score = self._calculate_risk_score()

        return {
            "scan_metadata": {
                "scan_type": "SAST",
                "tool": "ESLint Security + No-Secrets",
                "scan_date": datetime.now().isoformat(),
                "project": "ChronoGaz",
                "parser_version": "1.0.0"
            },
            "summary": {
                "total_files_scanned": self.stats["total_files_scanned"],
                "files_with_issues": self.stats["files_with_issues"],
                "total_vulnerabilities": self.stats["total_vulnerabilities"],
                "risk_score": risk_score,
                "severity_distribution": dict(self.stats["by_severity"]),
                "component_distribution": dict(self.stats["by_component"])
            },
            "top_vulnerabilities": sorted(
                self.vulnerabilities,
                key=lambda x: (
                    {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["risk_level"], 4),
                    x["location"]["file"]
                )
            )[:20],
            "statistics": {
                "by_type": dict(self.stats["by_type"]),
                "by_cwe": dict(self.stats["by_cwe"]),
                "by_owasp": dict(self.stats["by_owasp"])
            }
        }

    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-100)"""
        if self.stats["total_vulnerabilities"] == 0:
            return 0.0

        weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
        total_weight = sum(
            self.stats["by_severity"].get(sev, 0) * weight
            for sev, weight in weights.items()
        )

        max_possible = self.stats["total_vulnerabilities"] * weights["critical"]
        return round((total_weight / max_possible) * 100, 2)

    def save_report(self, output_path: str):
        """Save unified report to JSON file"""
        report = self._generate_report()

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"\n✅ Report saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Parse and unify SAST reports")
    parser.add_argument("-i", "--input-dir", default=".", help="Directory containing SAST reports")
    parser.add_argument("-o", "--output", default="unified_sast_report.json", help="Output file path")

    args = parser.parse_args()

    sast_parser = SASTParser(report_dir=args.input_dir)
    report = sast_parser.parse_all_reports()
    sast_parser.save_report(args.output)

    # Display top vulnerabilities summary
    top_vulns = report["top_vulnerabilities"]
    if top_vulns:
        print("\n🔝 Top Vulnerabilities:")
        for i, vuln in enumerate(top_vulns[:5], 1):
            print(f"{i}. [{vuln['risk_level'].upper()}] {vuln['type']}")
            print(f"   File: {vuln['location']['file']}:{vuln['location']['line']}")
            print(f"   CWE: {vuln['cwe']} | OWASP: {vuln['owasp_category']}")
    else:
        print("\n✅ No vulnerabilities found!")


if __name__ == "__main__":
    main()
