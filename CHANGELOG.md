# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-02

### Added

- `isIPsafe` node with IP (Check, Get Reports, Report, Clear Reports), Network (Check Block), Blocklist (Get) and Bulk (Report) operations.
- `isIPsafe API` credential sending the key as a Bearer header, with a credential test.
- `isMalicious` on IP Check that ignores allowlisted addresses and addresses without reports.
- Duplicate reports (HTTP 429) returned as `duplicate: true` instead of failing.
- Lookups without a credential, retries with backoff for lookups, client-side IP and CIDR validation.
- Usable as an AI agent tool.
