// bench/scenarios/unknown-principal/cedar/policies.cedar
// OpenAPL policy unknown-principal 1.0.0. principal = the caller; context.origin = the human
// (or context.origin_agent: require_human_origin is false).

// Grant everyone-reads (grant_to "*"): every caller.
@id("everyone-reads")
permit (principal, action == Action::"notes.read", resource)
when { resource.path like "note/*" };

// The origin must itself hold a grant (P2); "*" selects every origin.
@id("origin-has-no-grant")
forbid (principal, action, resource)
unless { action == Action::"notes.read" && resource.path like "note/*" };

// Every agent link must be a principal of this policy (P5).
@id("unknown-principal")
forbid (principal, action, resource)
unless {
  [Agent::"known-agent", Agent::"known-relay"].containsAll(context.agents)
};

// Human -> agent edge: known-agent acts_for group:staff on notes.read.
@id("no-acts-for-edge")
forbid (principal, action, resource)
when { context has first_agent }
unless {
  context has origin && context.first_agent == Agent::"known-agent" &&
  context.origin in Group::"staff" && action == Action::"notes.read"
};

// Agent -> agent edge known-agent -> known-relay (context.hops computed outside Cedar).
@id("no-may-delegate-edge")
forbid (principal, action, resource)
unless {
  ["known-agent>known-relay"].containsAll(context.hops) &&
  action == Action::"notes.read"
};
