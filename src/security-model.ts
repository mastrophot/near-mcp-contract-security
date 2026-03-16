import { ContractLanguage } from "./scanner.js";

export interface SecurityModelComparison {
  target_language: ContractLanguage;
  summary: string;
  near_strengths: string[];
  ethereum_strengths: string[];
  risk_tradeoffs: string[];
  scoring: {
    reentrancy_resilience: { near: number; ethereum: number };
    access_control_safety: { near: number; ethereum: number };
    oracle_mev_exposure: { near: number; ethereum: number };
    tooling_maturity: { near: number; ethereum: number };
  };
}

export interface ChecklistItem {
  id: string;
  severity: "low" | "medium" | "high";
  title: string;
  check: string;
  near_specific: boolean;
}

export interface AuditChecklist {
  language: ContractLanguage;
  checklist: ChecklistItem[];
  near_priority_items: ChecklistItem[];
}

export function compareSecurityModels(language: ContractLanguage): SecurityModelComparison {
  return {
    target_language: language,
    summary:
      "NEAR reduces classic synchronous reentrancy risk and gives account-level key scoping, while Ethereum offers deeper static-analysis ecosystem maturity.",
    near_strengths: [
      "No same-transaction synchronous reentrancy attack surface in the EVM sense",
      "Account and access-key model enables narrowly scoped permissions",
      "Deterministic gas model and explicit async promises improve execution clarity"
    ],
    ethereum_strengths: [
      "Large audit ecosystem and mature scanner/toolchain coverage",
      "Broadly battle-tested standards/libraries for contract hardening",
      "Deeper off-the-shelf monitoring and MEV analytics integrations"
    ],
    risk_tradeoffs: [
      "NEAR async callbacks still require careful state machine and idempotency design",
      "Oracle and price-manipulation risk exist on both chains if freshness checks are weak",
      "Access control remains application-layer responsibility in any model"
    ],
    scoring: {
      reentrancy_resilience: { near: 95, ethereum: 70 },
      access_control_safety: { near: 88, ethereum: 84 },
      oracle_mev_exposure: { near: 76, ethereum: 72 },
      tooling_maturity: { near: 78, ethereum: 94 }
    }
  };
}

export function auditChecklist(language: ContractLanguage): AuditChecklist {
  const checklist: ChecklistItem[] = [
    {
      id: "ac-01",
      severity: "high",
      title: "Privileged methods protected",
      check: "All admin/upgrade/mint/withdraw paths enforce explicit role or owner checks.",
      near_specific: false
    },
    {
      id: "ac-02",
      severity: "high",
      title: "External call ordering",
      check: "State updates follow safe ordering around external calls; callbacks are idempotent.",
      near_specific: false
    },
    {
      id: "math-01",
      severity: "medium",
      title: "Arithmetic bounds",
      check: "Critical arithmetic uses checked or constrained operations; no silent overflow assumptions.",
      near_specific: false
    },
    {
      id: "oracle-01",
      severity: "high",
      title: "Oracle freshness & sanity",
      check: "Oracle values enforce heartbeat/freshness checks plus sanity bounds or TWAP/median validation.",
      near_specific: false
    },
    {
      id: "mev-01",
      severity: "medium",
      title: "MEV/front-running mitigation",
      check: "Slippage limits, commit-reveal, or delayed execution strategies are applied where needed.",
      near_specific: false
    },
    {
      id: "near-01",
      severity: "high",
      title: "Predecessor/current account checks",
      check: "NEAR methods gate sensitive actions with predecessor/current account assertions.",
      near_specific: true
    },
    {
      id: "near-02",
      severity: "medium",
      title: "Promise callback safety",
      check: "Callbacks validate context and avoid double execution/state desync in async flows.",
      near_specific: true
    },
    {
      id: "near-03",
      severity: "low",
      title: "Access-key minimization",
      check: "Operational keys are scoped to minimal permissions and rotated on schedule.",
      near_specific: true
    }
  ];

  const nearPriorityItems = checklist.filter((x) => x.near_specific);
  return { language, checklist, near_priority_items: nearPriorityItems };
}
