# Security Policy

[Endor Labs](https://endorlabs.com) accepts reports of security vulnerabilities in this repository. Currently, no version support constraints are imposed; reports for any version are accepted

## Reporting a Vulnerability

This repository ***DOES NOT ACCEPT* automated scan results or reports** -- you *must* have a qualified human verify any such results before submitting them.

Please reference the specifc SHA ref of the version and file path in your reports and send email to `security`[at]`endor.ai`. Pull requests with security fixes are welcome, as long as they're not auto-generated.

- We generally aim to acknowledge security reports within one business day; however please allow up to 5
- Please coordinate with us on releasing details of serious vulnerabilities, to ensure a fix is available before wide disclosure
- Note that dependency-related vulnerabilities are automatically monitored and triaged for repair; reports like "your dependency X has CVE y" may not recieve a response

### A good report

A good security report helps us clearly identify and quickly respond. It includes:

- the exact git ref (SHA) where you identified the issue
- information about the exploitability of the issue -- how it can be exploited, and what access is required -- significantly helps with both triage and response
- a narrow, clear PR with a fix is extremely welcome and helpful
