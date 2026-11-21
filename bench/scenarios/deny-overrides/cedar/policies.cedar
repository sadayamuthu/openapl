// bench/scenarios/deny-overrides/cedar/policies.cedar
// OpenAPL policy deny-overrides 1.0.0. principal = the caller; context.origin = the human.
// Cedar's forbid-overrides-permit is OpenAPL's deny-overrides (P3).

// Caller grants.
@id("transfer-agent-transfers")
permit (principal == Agent::"transfer-agent", action == Action::"finance.transfer", resource)
when { resource.path like "ledger/*" };

@id("treasury-transfers")
permit (principal in Group::"treasury", action == Action::"finance.transfer", resource)
when { resource.path like "ledger/*" };

// The origin must itself hold a grant (P2).
@id("origin-has-no-grant")
forbid (principal, action, resource)
unless {
  context has origin && context.origin in Group::"treasury" &&
  action == Action::"finance.transfer" && resource.path like "ledger/*"
};

// Human -> agent edges: router-agent and transfer-agent act_for group:treasury.
@id("no-acts-for-edge")
forbid (principal, action, resource)
when { context has first_agent }
unless {
  context has origin &&
  [Agent::"router-agent", Agent::"transfer-agent"].contains(context.first_agent) &&
  context.origin in Group::"treasury" && action == Action::"finance.transfer"
};

// Agent -> agent edge router-agent -> transfer-agent (context.hops computed outside Cedar).
@id("no-may-delegate-edge")
forbid (principal, action, resource)
unless {
  ["router-agent>transfer-agent"].containsAll(context.hops) &&
  action == Action::"finance.transfer"
};

// Denies, checked on every link: context.agents is the set of agent links, context.origin
// the human (the only link a group: selector can match).
@id("no-frozen-ledgers")
forbid (principal, action == Action::"finance.transfer", resource)
when { resource.path like "ledger/frozen-*" };

@id("router-suspended")
forbid (principal, action == Action::"finance.transfer", resource)
when { context.agents.contains(Agent::"router-agent") && resource.path like "ledger/*" };

@id("no-contractors")
forbid (principal, action == Action::"finance.transfer", resource)
when {
  context has origin && context.origin in Group::"contractors" &&
  resource.path like "ledger/*"
};
