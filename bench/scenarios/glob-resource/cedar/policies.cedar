// bench/scenarios/glob-resource/cedar/policies.cedar
// OpenAPL policy glob-resource 1.0.0. principal = the caller; context.origin = the human.

// Caller grants (OpenAPL grades the caller).
@id("wiki-agent-read-docs")
permit (principal == Agent::"wiki-agent", action == Action::"docs.read", resource)
when { resource.path like "docs/*" };

@id("staff-read-docs")
permit (principal in Group::"staff", action == Action::"docs.read", resource)
when { resource.path like "docs/*" };

// The origin must itself hold a grant (P2).
@id("origin-has-no-grant")
forbid (principal, action, resource)
unless {
  context has origin && context.origin in Group::"staff" &&
  action == Action::"docs.read" && resource.path like "docs/*"
};

// Delegation edges: wiki-agent acts_for group:staff on docs.read; no may_delegate edges.
@id("no-acts-for-edge")
forbid (principal is Agent, action, resource)
unless {
  context has origin && principal == Agent::"wiki-agent" &&
  context.origin in Group::"staff" && action == Action::"docs.read"
};

// No may_delegate edges: an agent caller must be the chain's only agent, so it is also the
// agent the human handed the work to (the acts_for edge above is checked on the caller).
@id("no-may-delegate-edge")
forbid (principal is Agent, action, resource)
unless { [principal].containsAll(context.agents) };

// Deny no-salary-pages (grant_to "*": every link).
@id("no-salary-pages")
forbid (principal, action == Action::"docs.read", resource)
when { resource.path like "docs/hr/salaries*" };
