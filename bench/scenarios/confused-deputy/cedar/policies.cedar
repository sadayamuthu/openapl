// bench/scenarios/confused-deputy/cedar/policies.cedar
// OpenAPL policy confused-deputy 1.0.0. principal = the caller; context.origin = the human.

// Caller grants.
@id("export-agent-exports")
permit (principal == Agent::"export-agent", action == Action::"data.export", resource)
when { resource.path like "dataset/*" };

@id("finance-exports")
permit (principal in Group::"finance", action == Action::"data.export", resource)
when { resource.path like "dataset/*" };

// The origin must itself hold a grant (P2): the agent's grant does not cover the human.
@id("origin-has-no-grant")
forbid (principal, action, resource)
unless {
  context has origin && context.origin in Group::"finance" &&
  action == Action::"data.export" && resource.path like "dataset/*"
};

// Delegation edges: export-agent acts_for group:staff on data.export.
@id("no-acts-for-edge")
forbid (principal is Agent, action, resource)
unless {
  context has origin && principal == Agent::"export-agent" &&
  context.origin in Group::"staff" && action == Action::"data.export"
};

// No may_delegate edges: an agent caller must be the chain's only agent, so it is also the
// agent the human handed the work to (the acts_for edge above is checked on the caller).
@id("no-may-delegate-edge")
forbid (principal is Agent, action, resource)
unless { [principal].containsAll(context.agents) };
