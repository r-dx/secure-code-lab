# Automation disclosure

The scheduled workflow runs Tuesday and Friday at 02:17 UTC, plus on manual dispatch. It installs the pinned test dependency and validates every example against safe local fixtures. It has read-only repository permission, uses GitHub-hosted runners, stores no secrets, scans no external targets, and creates no commits. Routine validation is automated; it is not represented as manual research.
