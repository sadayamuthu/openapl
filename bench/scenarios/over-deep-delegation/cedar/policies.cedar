// bench/scenarios/over-deep-delegation/cedar/policies.cedar
// OpenAPL policy deep-chain 1.0.0. principal = the caller; context.origin = the human.

// Caller grants.
@id("agents-run")
permit (principal is Agent, action == Action::"report.run", resource)
when {
  [Agent::"agent-a", Agent::"agent-b", Agent::"agent-c"].contains(principal) &&
  resource.path like "report/*"
};

@id("analysts-run")
permit (principal in Group::"analysts", action == Action::"report.run", resource)
when { resource.path like "report/*" };

// The origin must itself hold a grant (P2).
@id("origin-has-no-grant")
forbid (principal, action, resource)
unless {
  context has origin && context.origin in Group::"analysts" &&
  action == Action::"report.run" && resource.path like "report/*"
};

// Human -> agent edge: agent-a acts_for group:analysts on report.run.
@id("no-acts-for-edge")
forbid (principal, action, resource)
when { context has first_agent }
unless {
  context has origin && context.first_agent == Agent::"agent-a" &&
  context.origin in Group::"analysts" && action == Action::"report.run"
};

// Agent -> agent edges a -> b -> c (context.hops computed outside Cedar).
@id("no-may-delegate-edge")
forbid (principal, action, resource)
unless {
  ["agent-a>agent-b", "agent-b>agent-c"].containsAll(context.hops) &&
  action == Action::"report.run"
};

// delegation.max_depth: 2. Cedar sets have no size, so context.depth = len(chain) - 1 is
// computed outside Cedar.
@id("max-depth")
forbid (principal, action, resource)
when { context.depth > 2 };
