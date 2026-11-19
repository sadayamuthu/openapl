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
forbid (principal, action, resource)
when { context has first_agent }
unless {
  context has origin && context.first_agent == Agent::"wiki-agent" &&
  context.origin in Group::"staff" && action == Action::"docs.read"
};

@id("no-may-delegate-edge")
forbid (principal, action, resource)
when { !context.hops.isEmpty() };

// Deny no-salary-pages (grant_to "*": every link).
@id("no-salary-pages")
forbid (principal, action == Action::"docs.read", resource)
when { resource.path like "docs/hr/salaries*" };
