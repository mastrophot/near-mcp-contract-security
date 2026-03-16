# Why NEAR Contracts Can Be Inherently Safer for Several Attack Classes

Smart contract security incidents still cluster around predictable classes: reentrancy, weak access control, oracle abuse, and MEV-sensitive execution paths.

NEAR does not remove the need for audits, but it changes default risk at the execution-model level:

1. No classic same-transaction synchronous reentrancy path.
2. Account + access-key model gives stronger permission granularity.
3. Async promise architecture forces explicit callback/state design.

In practice, teams still need:
- explicit authorization checks,
- oracle freshness/sanity validation,
- idempotent callback handling,
- invariant tests.

This is why the best approach is model-aware security automation: scan known anti-patterns, then score and explain how chain architecture changes risk weighting.

`mcp-contract-security` was built to make that workflow easy inside MCP-compatible agents.
