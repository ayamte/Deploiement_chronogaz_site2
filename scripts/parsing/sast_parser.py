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
      
    RISK_LEVELS = {  
        "security/detect-eval-with-expression": "high",  
        "security/detect-object-injection": "medium",  
        "security/detect-child-process": "high",  
        "security/detect-non-literal-regexp": "medium",  
        "no-secrets/no-secrets": "critical",  
    }  
  
    def __init__(self, report_dir: str):  
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
  
    def parse_all_reports(self) -> Dict:  
        print("=" * 70)  
        print("🔍 SAST PARSER - Static Application Security Testing")  
        print("=" * 70)  
          
        client_report = self.report_dir / "sast-eslint-client.json"  
        if client_report.exists():  
            print(f"\n📄 Parsing client report: {client_report}")  
            self._parse_eslint_report(client_report, "client")  
          
        api_report = self.report_dir / "sast-eslint-api.json"  
        if api_report.exists():  
            print(f"📄 Parsing API report: {api_report}")  
            self._parse_eslint_report(api_report, "api")  
          
        # ✅ DÉDUPLICATION CRITIQUE  
        print(f"\n🔄 Déduplication des vulnérabilités...")  
        original_count = len(self.vulnerabilities)  
        self._deduplicate_vulnerabilities()  
        deduplicated_count = len(self.vulnerabilities)  
        print(f"   Avant : {original_count} vulnérabilités")  
        print(f"   Après : {deduplicated_count} vulnérabilités uniques")  
        print(f"   Doublons éliminés : {original_count - deduplicated_count}")  
          
        # Validation  
        self._validate_deduplication()  
          
        self._compute_statistics()  
        self._print_summary()  
          
        return self._generate_report()  
  
    def _parse_eslint_report(self, report_path: Path, component: str):  
        with open(report_path, 'r', encoding='utf-8') as f:  
            data = json.load(f)  
          
        for file_result in data:  
            file_path = file_result.get("filePath", "")  
            messages = file_result.get("messages", [])  
              
            self.stats["total_files_scanned"] += 1  
              
            if messages:  
                self.stats["files_with_issues"] += 1  
              
            for msg in messages:  
                vuln = self._create_vulnerability_entry(msg, file_path, component)  
                self.vulnerabilities.append(vuln)  
  
    def _create_vulnerability_entry(self, msg: Dict, file_path: str, component: str) -> Dict:  
        rule_id = msg.get("ruleId", "unknown")  
        severity = self.SEVERITY_MAP.get(msg.get("severity", 1), "warning")  
          
        # Générer un ID unique basé sur le contenu  
        vuln_id = self._generate_vuln_id(file_path, msg.get("line", 0), rule_id)  
          
        return {  
            "id": vuln_id,  
            "source": "SAST",  
            "tool": "ESLint-Security",  
            "component": component,  
            "rule_id": rule_id,  
            "type": self._get_vulnerability_type(rule_id),  
            "severity": severity,  
            "risk_level": self._get_risk_level(rule_id),  
            "message": msg.get("message", ""),  
            "description": self._enrich_description(rule_id, msg.get("message", "")),  
            "location": {  
                "file": self._normalize_file_path(file_path),  
                "line": msg.get("line", 0),  
                "column": msg.get("column", 0),  
                "end_line": msg.get("endLine", msg.get("line", 0)),  
                "end_column": msg.get("endColumn", msg.get("column", 0)),  
            },  
            "cwe": self.CWE_MAPPING.get(rule_id, "CWE-Unknown"),  
            "recommendation": self._get_recommendation(rule_id),  
            "owasp_category": self._map_to_owasp(self.CWE_MAPPING.get(rule_id, "")),  
            "nist_csf_function": self._map_to_nist_csf(self.CWE_MAPPING.get(rule_id, "")),  
        }  
  
    def _generate_vuln_id(self, file_path: str, line: int, rule_id: str) -> str:  
        """Génère un ID unique pour chaque vulnérabilité."""  
        import hashlib  
        content = f"{file_path}:{line}:{rule_id}"  
        return f"SAST-{hashlib.md5(content.encode()).hexdigest()[:8].upper()}"  
  
    def _deduplicate_vulnerabilities(self):  
        """Déduplique les vulnérabilités par (file, line, rule_id)."""  
        seen = {}  
        deduplicated = []  
          
        for vuln in self.vulnerabilities:  
            # Clé de déduplication : (fichier, ligne, règle)  
            key = (  
                vuln['location']['file'],  
                vuln['location']['line'],  
                vuln['rule_id']  
            )  
              
            if key not in seen:  
                seen[key] = vuln  
                deduplicated.append(vuln)  
            else:  
                # Si doublon, fusionner les colonnes multiples  
                existing = seen[key]  
                if 'multiple_detections' not in existing:  
                    existing['multiple_detections'] = []  
                existing['multiple_detections'].append({  
                    'column': vuln['location']['column'],  
                    'end_column': vuln['location']['end_column']  
                })  
          
        self.vulnerabilities = deduplicated  
  
    def _validate_deduplication(self) -> bool:  
        """Vérifie qu'il n'y a pas de doublons après déduplication."""  
        seen_keys = set()  
        duplicates = []  
          
        for vuln in self.vulnerabilities:  
            key = (vuln['location']['file'], vuln['location']['line'], vuln['rule_id'])  
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
  
    def _normalize_file_path(self, file_path: str) -> str:  
        """Normalise le chemin de fichier pour enlever le préfixe GitHub Actions."""  
        parts = file_path.split("/")  
        if "client" in parts:  
            idx = parts.index("client")  
            return "/".join(parts[idx:])  
        elif "api" in parts:  
            idx = parts.index("api")  
            return "/".join(parts[idx:])  
        return file_path  
  
    def _get_vulnerability_type(self, rule_id: str) -> str:  
        type_map = {  
            "security/detect-eval-with-expression": "Code Injection",  
            "security/detect-object-injection": "Object Injection",  
            "security/detect-child-process": "Command Injection",  
            "security/detect-non-literal-regexp": "ReDoS",  
            "no-secrets/no-secrets": "Hardcoded Secrets",  
        }  
        return type_map.get(rule_id, "Security Issue")  
  
    def _get_risk_level(self, rule_id: str) -> str:  
        return self.RISK_LEVELS.get(rule_id, "low")  
  
    def _enrich_description(self, rule_id: str, original_message: str) -> str:  
        descriptions = {  
            "no-secrets/no-secrets": "Hardcoded secrets (passwords, API keys, tokens) in source code pose a critical security risk.",  
            "security/detect-eval-with-expression": "Using eval() with user input can lead to arbitrary code execution.",  
            "security/detect-object-injection": "Generic object injection can allow attackers to access or modify object properties.",  
            "security/detect-non-literal-regexp": "Non-literal regular expressions can lead to ReDoS attacks.",  
        }  
        base_desc = descriptions.get(rule_id, "Security vulnerability detected.")  
        return f"{base_desc} | Original: {original_message}"  
  
    def _get_recommendation(self, rule_id: str) -> str:  
        recommendations = {  
            "no-secrets/no-secrets": "Remove all hardcoded secrets from source code immediately.",  
            "security/detect-eval-with-expression": "Avoid using eval(). Use safer alternatives like JSON.parse().",  
            "security/detect-object-injection": "Validate and sanitize all object keys before using bracket notation.",  
            "security/detect-non-literal-regexp": "Review and simplify regular expressions to avoid catastrophic backtracking.",  
        }  
        return recommendations.get(rule_id, "Review and fix the security issue.")  
  
    def _map_to_owasp(self, cwe: str) -> str:  
        """Map CWE vers OWASP Top 10 2021."""  
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
        """Map CWE vers NIST CSF function."""  
        nist_map = {  
            'CWE-798': 'PR.AC - Access Control',  
            'CWE-95': 'PR.IP - Protective Technology',  
            'CWE-94': 'PR.DS - Data Security',  
            'CWE-78': 'PR.IP - Protective Technology',  
            'CWE-79': 'PR.DS - Data Security',  
            'CWE-400': 'DE.CM - Security Continuous Monitoring',  
            'CWE-1333': 'DE.CM - Security Continuous Monitoring',  
            'CWE-352': 'PR.AC - Access Control',  
            'CWE-208': 'PR.DS - Data Security',  
            'CWE-338': 'PR.DS - Data Security',  
        }  
        return nist_map.get(cwe, 'ID.RA - Risk Assessment')  
  
    def _compute_statistics(self):  
        self.stats["total_vulnerabilities"] = len(self.vulnerabilities)  
          
        for vuln in self.vulnerabilities:  
            self.stats["by_severity"][vuln["severity"]] += 1  
            self.stats["by_component"][vuln["component"]] += 1  
            self.stats["by_type"][vuln["rule_id"]] += 1  
            self.stats["by_cwe"][vuln["cwe"]] += 1  
            self.stats["by_owasp"][vuln["owasp_category"]] += 1  
  
    def _print_summary(self):  
        print("\n" + "=" * 70)  
        print("📊 SAST SCAN SUMMARY")  
        print("=" * 70)  
        print(f"Total files scanned: {self.stats['total_files_scanned']}")  
        print(f"Files with issues: {self.stats['files_with_issues']}")  
        print(f"Total vulnerabilities: {self.stats['total_vulnerabilities']}")  
        print(f"\nBy severity:")  
        for sev, count in self.stats["by_severity"].items():  
            print(f"  {sev}: {count}")  
        print(f"\nBy component:")  
        for comp, count in self.stats["by_component"].items():  
            print(f"  {comp}: {count}")  
  
    def _generate_report(self) -> Dict:  
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
                "  
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
        """Calculate overall risk score based on severity distribution."""  
        weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}  
        total_score = sum(  
            self.stats["by_severity"].get(sev, 0) * weight  
            for sev, weight in weights.items()  
        )  
        max_possible = self.stats["total_vulnerabilities"] * 10  
        return round((total_score / max(max_possible, 1)) * 100, 2)  
  
    def save_report(self, output_file: str):  
        """Save the unified report to a JSON file."""  
        report = self._generate_report()  
          
        with open(output_file, 'w', encoding='utf-8') as f:  
            json.dump(report, f, indent=2, ensure_ascii=False)  
          
        print(f"\n✅ Unified SAST report saved to: {output_file}")  
        print(f"📊 Total vulnerabilities: {self.stats['total_vulnerabilities']}")  
        print(f"🎯 Risk score: {report['summary']['risk_score']}/100")  
  
  
def main():  
    import argparse  
      
    parser = argparse.ArgumentParser(description="SAST Parser - Parse ESLint Security Reports")  
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
