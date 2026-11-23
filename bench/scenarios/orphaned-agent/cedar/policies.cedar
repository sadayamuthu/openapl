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

// Delegation edges: report-agent acts_for group:analysts on report.run.
@id("no-acts-for-edge")
forbid (principal is Agent, action, resource)
unless {
  context has origin && principal == Agent::"report-agent" &&
  context.origin in Group::"analysts" && action == Action::"report.run"
};

// No may_delegate edges: an agent caller must be the chain's only agent, so it is also the
// agent the human handed the work to (the acts_for edge above is checked on the caller).
@id("no-may-delegate-edge")
forbid (principal is Agent, action, resource)
unless { [principal].containsAll(context.agents) };

// Owner must be active in the snapshot. Checked for the caller (the only agent this policy
// allows); Cedar cannot map over context.agents to read every link's owner.
@id("owner-not-active")
forbid (principal is Agent, action, resource)
when { context has active_owners && !context.active_owners.contains(principal.owner) };
