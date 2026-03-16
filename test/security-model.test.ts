import { describe, expect, it } from "vitest";

import { auditChecklist, compareSecurityModels } from "../src/security-model.js";

describe("security model helpers", () => {
  it("returns comparison with scoring", () => {
    const result = compareSecurityModels("solidity");
    expect(result.near_strengths.length).toBeGreaterThan(0);
    expect(result.scoring.reentrancy_resilience.near).toBeGreaterThan(result.scoring.reentrancy_resilience.ethereum);
  });

  it("returns checklist with near-specific entries", () => {
    const result = auditChecklist("rust");
    expect(result.checklist.length).toBeGreaterThan(5);
    expect(result.near_priority_items.length).toBeGreaterThan(0);
  });
});
