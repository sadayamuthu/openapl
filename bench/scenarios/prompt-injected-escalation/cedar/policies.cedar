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
forbid (principal is Agent, action, resource)
unless {
  context has origin && principal == Agent::"helpdesk-agent" &&
  context.origin in Group::"support" && action == Action::"tickets.read"
};

// No may_delegate edges: an agent caller must be the chain's only agent, so it is also the
// agent the human handed the work to (the acts_for edge above is checked on the caller).
@id("no-may-delegate-edge")
forbid (principal is Agent, action, resource)
unless { [principal].containsAll(context.agents) };
