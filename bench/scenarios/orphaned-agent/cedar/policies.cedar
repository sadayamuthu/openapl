// bench/scenarios/orphaned-agent/cedar/policies.cedar
// OpenAPL policy orphaned-agent 1.0.0. principal = the caller; context.origin = the human.
// context.active_owners is the directory snapshot (absent when none is supplied).

// Caller grants.
@id("report-agent-run")
permit (principal == Agent::"report-agent", action == Action::"report.run", resource)
when { resource.path like "report/*" };

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

// Delegation edges: report-agent acts_for group:analysts on report.run; no may_delegate.
@id("no-acts-for-edge")
forbid (principal, action, resource)
when { context has first_agent }
unless {
  context has origin && context.first_agent == Agent::"report-agent" &&
  context.origin in Group::"analysts" && action == Action::"report.run"
};

@id("no-may-delegate-edge")
forbid (principal, action, resource)
when { !context.hops.isEmpty() };

// Owner must be active in the snapshot. Checked for the caller (the only agent this policy
// allows); Cedar cannot map over context.agents to read every link's owner.
@id("owner-not-active")
forbid (principal is Agent, action, resource)
when { context has active_owners && !context.active_owners.contains(principal.owner) };
