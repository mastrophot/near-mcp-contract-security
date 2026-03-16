import { describe, expect, it } from "vitest";

import { scanContract } from "../src/scanner.js";

describe("scanContract", () => {
  it("detects high-risk solidity patterns", () => {
    const code = `
pragma solidity ^0.7.6;
contract Vault {
  mapping(address=>uint256) public balances;
  function withdraw(uint256 amount) public {
    (bool ok,) = msg.sender.call("");
    require(ok, "fail");
    balances[msg.sender] -= amount;
  }
  function setOwner(address x) public { owner = x; }
}
`;

    const result = scanContract(code, "solidity");
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
    expect(result.vulnerabilities.some((v) => v.type === "reentrancy")).toBe(true);
    expect(result.vulnerabilities.some((v) => v.type === "integer_overflow_underflow")).toBe(true);
    expect(result.security_score).toBeLessThan(100);
    expect(result.near_equivalent_score).toBeGreaterThanOrEqual(result.security_score);
  });

  it("handles rust contract snippets", () => {
    const code = `
pub fn admin_withdraw(&mut self) {
    Promise::new(self.owner.clone()).transfer(1);
}
`;
    const result = scanContract(code, "rust");
    expect(result.language).toBe("rust");
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
  });

  it("returns clean recommendation on safe minimal code", () => {
    const code = `
contract Safe {
  function ping() external pure returns (bool) { return true; }
}
`;
    const result = scanContract(code, "solidity");
    expect(result.recommendation.length).toBeGreaterThan(0);
  });
});
