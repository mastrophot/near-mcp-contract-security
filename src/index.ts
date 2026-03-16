#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import { auditChecklist, compareSecurityModels } from "./security-model.js";
import { scanContract } from "./scanner.js";

const server = new Server(
  {
    name: "mcp-contract-security",
    version: "0.1.1"
  },
  {
    capabilities: {
      tools: {}
    }
  }
);

const scanSchema = z.object({
  code: z.string().min(1),
  language: z.enum(["rust", "solidity", "typescript"])
});

const compareSchema = z
  .object({
    language: z.enum(["rust", "solidity", "typescript"]).default("solidity")
  })
  .partial();

const checklistSchema = z
  .object({
    language: z.enum(["rust", "solidity", "typescript"]).default("solidity")
  })
  .partial();

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "scan_contract",
      description: "Scan contract code for common vulnerabilities and include NEAR-specific security notes.",
      inputSchema: {
        type: "object",
        properties: {
          code: { type: "string" },
          language: { type: "string", enum: ["rust", "solidity", "typescript"] }
        },
        required: ["code", "language"]
      }
    },
    {
      name: "compare_security_models",
      description: "Compare NEAR vs Ethereum security architecture and risk profile.",
      inputSchema: {
        type: "object",
        properties: {
          language: { type: "string", enum: ["rust", "solidity", "typescript"], default: "solidity" }
        },
        required: []
      }
    },
    {
      name: "audit_checklist",
      description: "Return a practical smart contract security checklist with NEAR-specific items.",
      inputSchema: {
        type: "object",
        properties: {
          language: { type: "string", enum: ["rust", "solidity", "typescript"], default: "solidity" }
        },
        required: []
      }
    }
  ]
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const tool = request.params.name;
  const args = request.params.arguments ?? {};

  try {
    if (tool === "scan_contract") {
      const parsed = scanSchema.parse(args);
      const result = scanContract(parsed.code, parsed.language);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }

    if (tool === "compare_security_models") {
      const parsed = compareSchema.parse(args);
      const result = compareSecurityModels(parsed.language ?? "solidity");
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }

    if (tool === "audit_checklist") {
      const parsed = checklistSchema.parse(args);
      const result = auditChecklist(parsed.language ?? "solidity");
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }

    return {
      isError: true,
      content: [{ type: "text", text: JSON.stringify({ error: "unknown_tool", tool }, null, 2) }]
    };
  } catch (err) {
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: JSON.stringify({ error: "tool_error", message: err instanceof Error ? err.message : String(err) }, null, 2)
        }
      ]
    };
  }
});

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("mcp-contract-security failed:", err);
  process.exit(1);
});
