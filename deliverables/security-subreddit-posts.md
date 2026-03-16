# Security Subreddit Post Drafts

## r/smartcontracts
Title: Open-source MCP server for fast contract security triage (with NEAR model comparison)
Body: Built `mcp-contract-security` for AI-assisted contract review. It scans Solidity/Rust/TS code for reentrancy, access-control, arithmetic, oracle, and MEV patterns, then returns a structured finding set plus security scores. Includes a `compare_security_models` tool that explains where NEAR's execution model can reduce specific attack classes.

## r/ethdev
Title: Contract scanner MCP tool for Claude/Cursor workflows
Body: If you review contracts inside agent workflows, this MCP server adds `scan_contract`, `audit_checklist`, and `compare_security_models`. Not a replacement for formal audits, but useful as a deterministic first-pass triage step.
