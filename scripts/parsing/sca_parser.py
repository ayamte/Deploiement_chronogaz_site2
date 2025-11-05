import os
import json
import argparse
from pathlib import Path
from collections import defaultdict
from typing import List, Dict


class SCAParser:
    """Parser pour fusionner et normaliser les rapports SCA (NPM + OWASP Dependency Check)."""

    SEVERITY_MAP = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
    }

    def __init__(self, report_dir: str, output_file: str):
        self.report_dir = Path(report_dir)
        self.output_file = Path(output_file)
        self.vulnerabilities: List[Dict] = []
        self.stats = {
            "total_packages": 0,
            "vulnerable_packages": 0,
            "total_vulnerabilities": 0,
            "by_severity": defaultdict(int),
            "by_component": defaultdict(int),
            "by_package": defaultdict(int),
        }

    # ===============================
    # Main parsing orchestration
    # ===============================
    def parse_all_reports(self) -> Dict:
        print("=" * 70)
        print("🔍 SCA PARSER - Global Dependency Analysis")
        print("=" * 70)

        # --- 1. NPM Audit Reports ---
        reports = [
            ("sca-client-production.json", "client", "production"),
            ("sca-client-vulnerable.json", "client", "vulnerable"),
            ("sca-api-production.json", "api", "production"),
            ("sca-api-vulnerable.json", "api", "vulnerable"),
        ]

        for filename, component, variant in reports:
            report_path = self.report_dir / filename
            if report_path.exists():
                vulns = self.parse_npm_audit(str(report_path), component, variant)
                self.vulnerabilities.extend(vulns)
            else:
                print(f"⚠️ Missing NPM report: {report_path}")

        # --- 2. OWASP Dependency Check ---
        depcheck_path = self.report_dir / "dependency-check-reports" / "dependency-check-report.json"
        if depcheck_path.exists():
            print(f"\n📦 Parsing OWASP Dependency Check report: {depcheck_path}")
            vulns = self.parse_dependency_check(str(depcheck_path))
            self.vulnerabilities.extend(vulns)
        else:
            print("⚠️ No OWASP Dependency Check report found.")

        # --- 3. Generate unified report ---
        report = self._generate_unified_report()

        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print("\n✅ Unified SCA report generated successfully!")
        print(f"📄 Output: {self.output_file}\n")

        return report

    # ===============================
    # NPM Audit Parser
    # ===============================
    def parse_npm_audit(self, report_path: str, component: str, variant: str) -> List[Dict]:
        vulns = []
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            advisories = data.get("vulnerabilities", {}) or data.get("advisories", {})
            if not advisories:
                print(f"✅ No vulnerabilities in {report_path}")
                return []

            for pkg, info in advisories.items():
                severity = info.get("severity", "info").lower()
                vuln_entry = {
                    "id": info.get("id", pkg),
                    "source": "SCA",
                    "tool": "npm audit",
                    "component": component,
                    "variant": variant,
                    "package": pkg,
                    "severity": self.SEVERITY_MAP.get(severity, "info"),
                    "risk_level": self._calculate_risk_level(severity, [info.get("cvss", 0)]),
                    "description": info.get("title", info.get("url", "N/A")),
                    "cvss_scores": [info.get("cvss", 0)],
                    "max_cvss": info.get("cvss", 0),
                    "advisories": [{"url": info.get("url")}] if info.get("url") else [],
                    "fix_available": info.get("fixAvailable", False),
                    "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                    "nist_csf_function": "PR.IP - Protective Technology",
                }
                vulns.append(vuln_entry)
                self._update_stats(pkg, severity, component)
            print(f"✅ Parsed NPM report {report_path}: {len(vulns)} vulnerabilities")
        except Exception as e:
            print(f"❌ Error parsing NPM report {report_path}: {e}")
        return vulns

    # ===============================
    # OWASP Dependency Check Parser
    # ===============================
    def parse_dependency_check(self, report_path: str) -> List[Dict]:
        vulns = []
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            dependencies = data.get("dependencies", [])
            for dep in dependencies:
                pkg_name = dep.get("fileName") or dep.get("name") or "unknown"
                for vuln in dep.get("vulnerabilities", []) or []:
                    severity = vuln.get("severity", "info").lower()
                    cvss = (
                        vuln.get("cvssv3", {}).get("baseScore")
                        or vuln.get("cvssv2", {}).get("score")
                        or 0
                    )
                    vuln_entry = {
                        "id": vuln.get("name") or vuln.get("cve") or "UNKNOWN",
                        "source": "SCA",
                        "tool": "OWASP Dependency Check",
                        "component": "dependency-check",
                        "variant": "analysis",
                        "package": pkg_name,
                        "severity": self.SEVERITY_MAP.get(severity, "info"),
                        "risk_level": self._calculate_risk_level(severity, [cvss]),
                        "description": vuln.get("description", "").strip(),
                        "cvss_scores": [cvss],
                        "max_cvss": cvss,
                        "cwe": vuln.get("cwes", []),
                        "advisories": [
                            {"url": ref.get("url")}
                            for ref in vuln.get("references", [])
                            if ref.get("url")
                        ],
                        "fix_available": False,
                        "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                        "nist_csf_function": "ID.RA - Risk Assessment",
                    }
                    vulns.append(vuln_entry)
                    self._update_stats(pkg_name, severity, "dependency-check")
            print(f"✅ Parsed Dependency Check: {len(vulns)} vulnerabilities")
        except Exception as e:
            print(f"❌ Error parsing Dependency Check report: {e}")
        return vulns

    # ===============================
    # Helpers
    # ===============================
    def _update_stats(self, pkg, severity, component):
        self.stats["total_vulnerabilities"] += 1
        self.stats["by_severity"][severity] += 1
        self.stats["by_component"][component] += 1
        self.stats["by_package"][pkg] += 1

    def _calculate_risk_level(self, severity: str, scores: List[float]) -> str:
        if severity == "critical" or max(scores, default=0) >= 9:
            return "Severe"
        elif severity == "high" or max(scores, default=0) >= 7:
            return "High"
        elif severity == "medium":
            return "Moderate"
        elif severity == "low":
            return "Low"
        else:
            return "Informational"

    def _generate_unified_report(self) -> Dict:
        return {
            "summary": {
                "total_packages": len(self.stats["by_package"]),
                "vulnerable_packages": len(
                    [p for p, c in self.stats["by_package"].items() if c > 0]
                ),
                "total_vulnerabilities": self.stats["total_vulnerabilities"],
                "by_severity": dict(self.stats["by_severity"]),
                "by_component": dict(self.stats["by_component"]),
                "risk_score": self._calculate_global_risk_score(),
            },
            "vulnerabilities": self.vulnerabilities,
        }

    def _calculate_global_risk_score(self) -> int:
        weights = {"critical": 5, "high": 3, "medium": 2, "low": 1}
        score = sum(
            count * weights.get(sev, 0) for sev, count in self.stats["by_severity"].items()
        )
        return min(int((score / max(1, self.stats["total_vulnerabilities"])) * 20), 100)


# ===============================
# Entry Point
# ===============================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse and unify SCA reports.")
    parser.add_argument("-i", "--input", required=True, help="Input directory with reports")
    parser.add_argument("-o", "--output", required=True, help="Output unified report path")

    args = parser.parse_args()
    sca_parser = SCAParser(args.input, args.output)
    sca_parser.parse_all_reports()
