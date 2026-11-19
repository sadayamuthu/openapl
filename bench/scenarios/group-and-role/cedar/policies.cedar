// bench/scenarios/group-and-role/cedar/policies.cedar
// OpenAPL policy group-and-role 1.0.0. principal = the caller; context.origin = the human,
// whose groups and roles claims are its Group and Role parents.

// Caller grants.
@id("ops-agent-restart")
permit (principal == Agent::"ops-agent", action == Action::"ops.restart", resource)
when { resource.path like "service/*" };

@id("oncall-restart")
permit (principal in Role::"oncall", action == Action::"ops.restart", resource)
when { resource.path like "service/*" };

// The origin must itself hold a grant (P2): the role, not the group.
@id("origin-has-no-grant")
forbid (principal, action, resource)
unless {
  context has origin && context.origin in Role::"oncall" &&
  action == Action::"ops.restart" && resource.path like "service/*"
};

// Delegation edges: ops-agent acts_for group:sre on ops.restart; no may_delegate.
@id("no-acts-for-edge")
forbid (principal, action, resource)
when { context has first_agent }
unless {
  context has origin && context.first_agent == Agent::"ops-agent" &&
  context.origin in Group::"sre" && action == Action::"ops.restart"
};

@id("no-may-delegate-edge")
forbid (principal, action, resource)
when { !context.hops.isEmpty() };
