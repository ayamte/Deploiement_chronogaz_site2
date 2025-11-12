**Policy Title:** Hardcoded Secrets Prevention Policy

**NIST CSF Reference:** PR.DS-5

**ISO 27001 Reference:** A.8.2.1

**Risk Level:** WARNING

**Policy Statement:**
Hardcoded secrets, such as database connection strings and passwords, are strictly prohibited in source code to prevent unauthorized access in the event of code exposure. All secrets must be managed through secure, centralized secret management systems.

**Implementation Requirements:**
1. Use a dedicated secrets management service (e.g., HashiCorp Vault, AWS Secrets Manager) to store and retrieve all credentials and connection strings.
2. Implement pre-commit hooks and CI/CD pipeline checks that scan for high-entropy strings and known secret patterns to block commits containing hardcoded secrets.
3. Mandate the use of environment variables or configuration files excluded from version control for any application configuration requiring sensitive data.
4. Conduct mandatory secure coding training that specifically addresses the risks and proper handling of secrets for all developers.

**Verification Method:**
1. SAST scanning integrated into the CI/CD pipeline to detect and fail builds on commits containing potential hardcoded secrets.
2. Periodic manual code reviews and automated secret scanning of the entire codebase to ensure no secrets are present.
3. Audit logs from the secrets management service to verify that applications are retrieving secrets dynamically at runtime.

**Consolidation Note:** 5 other similar issue(s) were also detected and are covered by this policy.

---

**Policy Title:** Generic Object Injection Prevention Policy

**NIST CSF Reference:** PR.DS-5

**ISO 27001 Reference:** A.8.25

**Risk Level:** WARNING

**Policy Statement:**
Applications must prevent generic object injection vulnerabilities by validating and sanitizing all user-supplied input used to access object properties. Object property access must be restricted to explicitly allowed properties only.

**Implementation Requirements:**
1. Implement strict input validation to reject any user input containing unexpected object property names or access patterns.
2. Use allow-list based approaches for dynamic property access, ensuring only pre-approved properties can be referenced.
3. Apply proper output encoding when displaying object property values to prevent client-side injection.
4. Conduct security-focused code reviews to identify and remediate unsafe object property access patterns.

**Verification Method:**
1. SAST scanning on commit to detect generic object injection vulnerabilities in source code.
2. Manual penetration testing targeting object property manipulation in application interfaces.
3. Code review checklists specifically addressing dynamic property access patterns.

**Consolidation Note:** 12 other similar issue(s) were also detected and are covered by this policy.

---

**Policy Title:** Arbitrary Code Execution Prevention Policy

**NIST CSF Reference:** PR.DS-5

**ISO 27001 Reference:** A.14.2.1

**Risk Level:** ERROR

**Policy Statement:**
The use of eval() with expressions that can lead to arbitrary code execution is strictly prohibited. All code must be reviewed and sanitized to prevent this vulnerability

**Implementation Requirements:**
1. Prohibit the use of eval() and similar functions in all new code development.
2. Implement static code analysis tools to detect and flag any usage of eval() during the development lifecycle.
3. Conduct mandatory secure code training for developers on the risks of arbitrary code execution and safe coding alternatives.
4. Establish a code review process that explicitly checks for and rejects any instances of unsafe eval() usage.

**Verification Method:**
1. SAST scanning on every code commit to detect and block any usage of eval().
2. Regular peer code reviews with a checklist item to verify absence of eval() and similar dangerous functions.
3. Periodic security audits of the codebase to identify and remediate any historical instances of unsafe eval() usage.

---

**Policy Title:** Unnamed High-Severity SCA Vulnerability Prevention Policy

**NIST CSF Reference:** PR.IP-12

**ISO 27001 Reference:** A.12.6.1

**Risk Level:** HIGH

**Policy Statement:**
All software components identified by Software Composition Analysis (SCA) tools as having high-severity vulnerabilities must be promptly remediated or have compensating controls applied. Unnamed or unclassified vulnerabilities from SCA sources must be treated with the highest priority due to their inherent uncertainty and potential impact.

**Implementation Requirements:**
1. Integrate and mandate the use of SCA tools into all CI/CD pipelines to automatically scan for and flag high-severity vulnerabilities, including those without a formal name or description.
2. Establish a formal process to investigate and classify any vulnerability flagged as "unnamed" by SCA tools within 24 hours of detection to determine the appropriate remediation action.
3. Maintain an inventory of all third-party and open-source software components used, and enforce a policy that prohibits the use of components with unresolved high-severity SCA findings in production environments.

**Verification Method:**
1. Review SCA tool reports and CI/CD pipeline logs weekly to confirm all high-severity vulnerabilities, including unnamed ones, are being detected and addressed.
2. Conduct periodic (e.g., monthly) audits of the software component inventory to verify that no components with unresolved high-severity SCA vulnerabilities are deployed in production.

**Consolidation Note:** 4 other similar issue(s) were also detected and are covered by this policy.

---

**Policy Title:** CSP: Failure to Define Directive with No Fallback Prevention Policy

**NIST CSF Reference:** PR.DS-5

**ISO 27001 Reference:** A.14.2.1

**Risk Level:** MEDIUM

**Policy Statement:**
All Content Security Policy (CSP) implementations must explicitly define all directives that lack a fallback mechanism to prevent unintended resource loading. Excluding such directives is prohibited as it is equivalent to allowing any resource.

**Implementation Requirements:**
1. Define and enforce a mandatory list of CSP directives (e.g., `default-src`, `script-src`, `object-src`, `base-uri`) that must be explicitly specified in all CSP headers.
2. Implement automated pre-deployment checks to validate that CSP headers include all required directives and do not omit any directive without a fallback.
3. Establish and maintain a secure-by-default CSP template that includes safe values for all required directives, to be used as a baseline for all web applications.
4. Conduct developer training on CSP best practices, emphasizing the risks of omitting directives and the requirement to define each one explicitly.

**Verification Method:**
1. DAST scanning of all web applications quarterly to detect CSP headers with missing required directives.
2. Automated CSP header validation in the CI/CD pipeline, failing builds that deploy with incomplete CSP directives.
3. Manual review of CSP headers during security design reviews for new or modified web applications.

---

**Policy Title:** Content Security Policy (CSP) Header Implementation Policy

**NIST CSF Reference:** PR.DS-5

**ISO 27001 Reference:** A.14.2.1

**Risk Level:** MEDIUM

**Policy Statement:**
All web applications must implement a Content Security Policy (CSP) HTTP header to mitigate cross-site scripting and data injection attacks. The CSP must restrict content sources to explicitly approved origins only.

**Implementation Requirements:**
1. Define and deploy a CSP header for all web application responses, specifying allowed sources for scripts, stylesheets, images, and other content types.
2. Configure the CSP header to disallow inline scripts and styles by default, using nonces or hashes if necessary for legitimate inline code.
3. Implement a process to review and update the CSP policy whenever new external resources or content sources are added to the application.
4. Test the CSP header in a staging environment to ensure it does not break legitimate application functionality before deployment to production.

**Verification Method:**
1. DAST scanning of all web applications to confirm proper CSP header presence and configuration.
2. Manual verification of HTTP response headers using browser developer tools during deployment and after significant changes.
3. Automated security testing in CI/CD pipelines to check for missing or misconfigured CSP headers.

---

**Policy Title:** Cross-Domain Misconfiguration Prevention Policy

**NIST CSF Reference:** PR.DS-5

**ISO 27001 Reference:** A.14.2.1

**Risk Level:** MEDIUM

**Policy Statement:**
All web servers must be configured to restrict Cross Origin Resource Sharing (CORS) headers to explicitly trusted domains only. This prevents unauthorized cross-domain data access and protects against data exfiltration.

**Implementation Requirements:**
1. Configure CORS headers to explicitly specify allowed origins, methods, and headers, avoiding the use of wildcards (`*`) for sensitive domains.
2. Implement server-side validation to reject CORS requests from origins not present on the pre-approved allowlist.
3. Ensure that credentials are not included in CORS requests unless explicitly required and the origin is fully trusted.
4. Integrate CORS configuration checks into the secure deployment pipeline to prevent misconfigurations from reaching production.

**Verification Method:**
1. DAST scanning quarterly to detect permissive CORS headers and validate allowed origins.
2. Manual review of web server configuration files during change management to ensure compliance with the allowlist policy.
3. Automated security testing in the CI/CD pipeline to scan for wildcard usage in CORS headers on each deployment.

---

**Policy Title:** Missing Anti-clickjacking Header Prevention Policy

**NIST CSF Reference:** PR.DS-5

**ISO 27001 Reference:** A.8.25

**Risk Level:** MEDIUM

**Policy Statement:**
All web application responses must include anti-clickjacking headers to prevent UI redress attacks. This is achieved by implementing either the Content-Security-Policy with 'frame-ancestors' directive or the X-Frame-Options header.

**Implementation Requirements:**
1. Configure web servers and application frameworks to include the X-Frame-Options header with a value of 'DENY' or 'SAMEORIGIN' in all HTTP responses.
2. Implement Content-Security-Policy headers with the 'frame-ancestors' directive specifying allowed origins or 'none' to prevent framing.
3. Include anti-clickjacking header validation in the secure development lifecycle and code review processes for all new web applications and features.
4. Document and maintain an inventory of all public-facing web applications subject to this policy requirement.

**Verification Method:**
1. Perform automated DAST scanning during development and prior to production deployment to detect missing anti-clickjacking headers.
2. Conduct periodic manual verification using browser developer tools or security testing tools to confirm proper header implementation.
3. Include anti-clickjacking header checks in continuous integration/continuous deployment (CI/CD) pipeline security gates.

---

**Policy Title:** Permissions Policy Header Implementation Policy

**NIST CSF Reference:** PR.DS-5

**ISO 27001 Reference:** A.8.1.2

**Risk Level:** LOW

**Policy Statement:**
All publicly accessible web applications must define and enforce a Permissions Policy HTTP header to restrict unauthorized access to sensitive browser features. This policy ensures user privacy by explicitly allowing or denying the use of specific client-side capabilities.

**Implementation Requirements:**
1. Define a comprehensive Permissions Policy header for each web application, explicitly specifying allowed features (e.g., camera, microphone, geolocation) and denying all others by default.
2. Configure web servers (e.g., Apache, Nginx) or application frameworks to automatically include the Permissions Policy header in all HTTP responses for web resources.
3. Integrate Permissions Policy header validation into the continuous integration/continuous deployment (CI/CD) pipeline to prevent deployment of non-compliant code.
4. Conduct developer training on the importance of the Permissions Policy header and provide templates for common use cases to ensure consistent implementation.

**Verification Method:**
1. Perform automated DAST scans as part of the release cycle to verify the presence and correctness of the Permissions Policy header.
2. Conduct manual verification using browser developer tools to inspect HTTP response headers for the Permissions Policy entry.
3. Implement automated checks in the CI/CD pipeline to validate the Permissions Policy header configuration before deployment to production.