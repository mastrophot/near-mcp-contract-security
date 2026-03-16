# mcp-contract-security

MCP server for smart contract security scanning.

Implements the required tools:
- `scan_contract`
- `compare_security_models`
- `audit_checklist`

Supports languages:
- `solidity`
- `rust`
- `typescript`

## What it checks

`scan_contract` currently detects heuristic patterns for:
- Reentrancy
- Integer overflow/underflow risk
- Access control issues
- Front-running exposure
- Oracle manipulation risk

The output includes:
- vulnerability list with severity/type/line
- `security_score`
- `near_equivalent_score`
- NEAR-specific security notes and recommendation

## Install

```bash
npm install -g mcp-contract-security
```

Published package:
- npm: https://www.npmjs.com/package/mcp-contract-security
- MCP Registry: https://registry.modelcontextprotocol.io/v0/servers/io.github.mastrophot%2Fcontract-security-scanner/versions/0.1.1

## MCP config (Claude Desktop)

```json
{
  "mcpServers": {
    "contract-security": {
      "command": "mcp-contract-security"
    }
  }
}
```

## Tool usage

### `scan_contract`
Input:

```json
{
  "code": "contract source code here",
  "language": "solidity"
}
```

### `compare_security_models`
Input (optional):

```json
{
  "language": "solidity"
}
```

### `audit_checklist`
Input (optional):

```json
{
  "language": "rust"
}
```

## Local development

```bash
npm install
npm run check
```

## Deliverable assets

Additional publish assets are prepared in `deliverables/`:
- `deliverables/mcp-registry-submission.md`
- `deliverables/security-subreddit-posts.md`
- `deliverables/blog-why-near-contracts-safer.md`
- `server.json` (MCP Registry metadata, schema-validated)

## License

MIT
