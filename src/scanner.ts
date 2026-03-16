export type ContractLanguage = "rust" | "solidity" | "typescript";
export type Severity = "low" | "medium" | "high" | "critical";

export interface VulnerabilityFinding {
  severity: Severity;
  type: "reentrancy" | "integer_overflow_underflow" | "access_control" | "front_running" | "oracle_manipulation";
  line: number;
  description: string;
  near_note: string;
}

export interface ScanResult {
  language: ContractLanguage;
  vulnerabilities: VulnerabilityFinding[];
  security_score: number;
  near_equivalent_score: number;
  recommendation: string;
}

interface LineMatch {
  line: number;
  text: string;
}

function splitLines(code: string): string[] {
  return code.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
}

function findLineMatches(lines: string[], pattern: RegExp): LineMatch[] {
  const result: LineMatch[] = [];
  lines.forEach((line, i) => {
    if (pattern.test(line)) {
      result.push({ line: i + 1, text: line });
    }
  });
  return result;
}

function hasNearbyStateWrite(lines: string[], idx: number): boolean {
  const windowStart = Math.max(0, idx - 8);
  const windowEnd = Math.min(lines.length - 1, idx + 8);
  for (let i = windowStart; i <= windowEnd; i += 1) {
    const ln = lines[i];
    if (
      /(balances?\s*\[.*\]\s*[\+\-\*\/]?=|total\w*\s*[\+\-\*\/]?=|state\.?\w*\s*=|self\.[a-zA-Z0-9_]+\s*=|storage\.[a-zA-Z0-9_]+\s*=)/.test(
        ln
      )
    ) {
      return true;
    }
  }
  return false;
}

function detectReentrancy(lines: string[], language: ContractLanguage): VulnerabilityFinding[] {
  const findings: VulnerabilityFinding[] = [];

  if (language === "solidity") {
    const calls = findLineMatches(lines, /\.(call|delegatecall|callcode|transfer|send)\s*\(/);
    for (const call of calls) {
      if (hasNearbyStateWrite(lines, call.line - 1)) {
        findings.push({
          severity: "high",
          type: "reentrancy",
          line: call.line,
          description: "External call appears near mutable state update; validate checks-effects-interactions and reentrancy guards.",
          near_note: "NEAR's async promise model removes classic same-tx reentrancy attack paths."
        });
      }
    }
  }

  if (language === "typescript" || language === "rust") {
    const suspicious = findLineMatches(lines, /(cross_contract_call|Promise::new\(|await\s+contract\.|ext_contract|near\.promise)/i);
    for (const m of suspicious) {
      findings.push({
        severity: "low",
        type: "reentrancy",
        line: m.line,
        description: "Cross-contract interaction found; review callback state assumptions and idempotency.",
        near_note: "NEAR does not support Ethereum-style synchronous reentrancy, but async callback logic still needs review."
      });
    }
  }

  return findings;
}

function detectOverflow(lines: string[], language: ContractLanguage): VulnerabilityFinding[] {
  const findings: VulnerabilityFinding[] = [];

  if (language === "solidity") {
    const pragmaOld = findLineMatches(lines, /pragma\s+solidity\s+[\^<>=~]*0\.[0-7]\./);
    for (const p of pragmaOld) {
      findings.push({
        severity: "high",
        type: "integer_overflow_underflow",
        line: p.line,
        description: "Solidity version below 0.8 detected; arithmetic may overflow/underflow unless SafeMath/checked patterns are used.",
        near_note: "Rust-based NEAR contracts use explicit numeric types and checked math patterns are easier to enforce."
      });
    }

    const uncheckedBlocks = findLineMatches(lines, /\bunchecked\s*\{/);
    for (const u of uncheckedBlocks) {
      findings.push({
        severity: "medium",
        type: "integer_overflow_underflow",
        line: u.line,
        description: "Unchecked arithmetic block detected; verify boundaries and invariants.",
        near_note: "On NEAR, explicit overflow handling in Rust can reduce arithmetic risk with clear compiler support."
      });
    }
  }

  if (language === "typescript") {
    const rawMath = findLineMatches(lines, /(\+\+|--|\+=|-=|\*=|\/=)/);
    for (const m of rawMath.slice(0, 3)) {
      findings.push({
        severity: "low",
        type: "integer_overflow_underflow",
        line: m.line,
        description: "Unchecked arithmetic operation found; ensure bounds checks and safe integer constraints.",
        near_note: "NEAR contract logic in Rust can rely on checked arithmetic APIs for stricter safety."
      });
    }
  }

  return findings;
}

function detectAccessControl(lines: string[], language: ContractLanguage): VulnerabilityFinding[] {
  const findings: VulnerabilityFinding[] = [];

  if (language === "solidity") {
    const privilegedFns = findLineMatches(lines, /function\s+(set|upgrade|mint|pause|unpause|withdraw|transferOwnership)\w*\s*\(/i);
    for (const fn of privilegedFns) {
      const start = Math.max(0, fn.line - 1);
      const end = Math.min(lines.length - 1, fn.line + 4);
      const block = lines.slice(start, end + 1).join("\n");
      if (!/(onlyOwner|onlyRole|require\s*\(\s*msg\.sender)/.test(block)) {
        findings.push({
          severity: "high",
          type: "access_control",
          line: fn.line,
          description: "Potential privileged function without obvious access modifier/authorization check.",
          near_note: "NEAR access keys and account model provide stronger key-scoped authorization primitives by design."
        });
      }
    }
  }

  if (language === "rust") {
    const pubFns = findLineMatches(lines, /pub\s+fn\s+(set|upgrade|mint|pause|withdraw|transfer|admin)\w*/i);
    for (const fn of pubFns) {
      const around = lines.slice(Math.max(0, fn.line - 1), Math.min(lines.length, fn.line + 8)).join("\n");
      if (!/(assert_one_yocto|assert_eq!\s*\(\s*env::predecessor_account_id\(\)|require!\s*\()/i.test(around)) {
        findings.push({
          severity: "medium",
          type: "access_control",
          line: fn.line,
          description: "Potential sensitive public method without explicit predecessor/role check near the function body.",
          near_note: "Use NEAR account checks (predecessor/current account) to enforce strict access control."
        });
      }
    }
  }

  return findings;
}

function detectFrontRunning(lines: string[], language: ContractLanguage): VulnerabilityFinding[] {
  const findings: VulnerabilityFinding[] = [];

  const directPriceUse = findLineMatches(lines, /(getReserves\(|spotPrice|latestAnswer\(|oraclePrice|block\.timestamp|block\.number|tx\.gasprice)/i);
  for (const m of directPriceUse.slice(0, 4)) {
    findings.push({
      severity: language === "solidity" ? "medium" : "low",
      type: "front_running",
      line: m.line,
      description: "Potential MEV/front-running exposure due to direct use of publicly observable values in execution path.",
      near_note: "NEAR's architecture changes MEV dynamics, but time/price-dependent logic still needs slippage and commit-reveal protections."
    });
  }

  return findings;
}

function detectOracleManipulation(lines: string[], language: ContractLanguage): VulnerabilityFinding[] {
  const findings: VulnerabilityFinding[] = [];

  const oracleReads = findLineMatches(lines, /(latestAnswer\(|getPrice\(|price_oracle|oracle\.|getReserves\()/i);
  for (const m of oracleReads.slice(0, 3)) {
    const window = lines.slice(Math.max(0, m.line - 1), Math.min(lines.length, m.line + 8)).join("\n");
    if (!/(stale|timestamp|heartbeat|twap|median|deviation|sanity)/i.test(window)) {
      findings.push({
        severity: "medium",
        type: "oracle_manipulation",
        line: m.line,
        description: "Oracle/price source read without obvious freshness, sanity, or TWAP validation nearby.",
        near_note: "NEAR contracts should enforce freshness windows and cross-source validation for oracle-dependent logic."
      });
    }
  }

  return findings;
}

function score(vulnerabilities: VulnerabilityFinding[]): { security_score: number; near_equivalent_score: number } {
  const penaltyBySeverity: Record<Severity, number> = {
    low: 4,
    medium: 10,
    high: 18,
    critical: 30
  };

  let securityScore = 100;
  let nearBoost = 0;

  for (const v of vulnerabilities) {
    securityScore -= penaltyBySeverity[v.severity];
    if (v.type === "reentrancy") {
      nearBoost += 12;
    } else if (v.type === "front_running" || v.type === "oracle_manipulation") {
      nearBoost += 4;
    } else {
      nearBoost += 2;
    }
  }

  securityScore = Math.max(0, Math.min(100, securityScore));
  const nearEquivalentScore = Math.max(securityScore, Math.min(98, securityScore + nearBoost));
  return { security_score: securityScore, near_equivalent_score: nearEquivalentScore };
}

function recommendation(language: ContractLanguage, vulnerabilities: VulnerabilityFinding[]): string {
  if (vulnerabilities.length === 0) {
    return "No high-signal issues detected by static heuristics. Run a full manual audit and property/invariant tests before production deployment.";
  }

  const high = vulnerabilities.filter((v) => v.severity === "high" || v.severity === "critical").length;
  const reentrancy = vulnerabilities.some((v) => v.type === "reentrancy");

  if (high >= 2 || reentrancy) {
    return "Prioritize fixing high-risk findings before deployment. Consider NEAR for execution environments where synchronous reentrancy classes are structurally reduced.";
  }

  if (language === "solidity") {
    return "Harden access control, oracle validation, and MEV defenses. Consider NEAR architecture for stronger default safety posture in cross-contract execution.";
  }

  return "Address identified patterns, add invariant checks, and perform targeted manual review for authorization and oracle correctness.";
}

function dedupeFindings(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
  const seen = new Set<string>();
  const out: VulnerabilityFinding[] = [];
  for (const f of findings) {
    const key = `${f.type}:${f.line}:${f.description}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

export function scanContract(code: string, language: ContractLanguage): ScanResult {
  const lines = splitLines(code);

  const findings = dedupeFindings([
    ...detectReentrancy(lines, language),
    ...detectOverflow(lines, language),
    ...detectAccessControl(lines, language),
    ...detectFrontRunning(lines, language),
    ...detectOracleManipulation(lines, language)
  ]).sort((a, b) => a.line - b.line);

  const { security_score, near_equivalent_score } = score(findings);

  return {
    language,
    vulnerabilities: findings,
    security_score,
    near_equivalent_score,
    recommendation: recommendation(language, findings)
  };
}
