# Changelog

## 2026-08-01

### Added
- Added authenticated scanning using session cookies and login credentials.

## 2026-08-02

### Improved
- Refactored scanner core for better readability and maintainability.
- Improved URL normalization and crawler efficiency.
- Enhanced vulnerability deduplication and thread safety.
- Optimized injection scanning workflow and request handling.
- Improved SQL Injection detection (Error, Boolean, Time-based).
- Improved Reflected and Stored XSS detection accuracy.
- Improved CSRF detection heuristics.
- Improved SSTI detection with better validation.
- Enhanced OWASP Top 10 detection logic (A01–A10).
- Reduced false positives across multiple scan modules.

### Fixed
- Fixed scan stability issues causing long-running scans.
- Fixed inconsistent variable naming and response handling.
- Fixed duplicate vulnerability reporting.
