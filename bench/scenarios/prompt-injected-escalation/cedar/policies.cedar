// bench/scenarios/prompt-injected-escalation/cedar/policies.cedar
// OpenAPL policy helpdesk 1.0.0. principal = the caller; context.origin = the human.

// Caller grants. The action glob tickets.* is the schema action group "tickets.*".
@id("helpdesk-agent-tool-binding")
permit (principal == Agent::"helpdesk-agent", action in Action::"tickets.*", resource)
when { resource.path like "ticket/*" };

@id("support-tickets")
permit (principal in Group::"support", action in Action::"tickets.*", resource)
when { resource.path like "ticket/*" };

// The origin must itself hold a grant (P2).
@id("origin-has-no-grant")
forbid (principal, action, resource)
unless {
  context has origin && context.origin in Group::"support" &&
  action in Action::"tickets.*" && resource.path like "ticket/*"
};

// Delegation edge: helpdesk-agent acts_for group:support on tickets.read only. This edge,
// not a grant, is what stops an injected tickets.delete or tickets.read-all.
@id("no-acts-for-edge")
forbid (principal, action, resource)
when { context has first_agent }
unless {
  context has origin && context.first_agent == Agent::"helpdesk-agent" &&
  context.origin in Group::"support" && action == Action::"tickets.read"
};

@id("no-may-delegate-edge")
forbid (principal, action, resource)
when { !context.hops.isEmpty() };
