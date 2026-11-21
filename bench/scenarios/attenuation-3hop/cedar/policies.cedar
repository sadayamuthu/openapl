// bench/scenarios/attenuation-3hop/cedar/policies.cedar
// OpenAPL policy attenuation-3hop 1.0.0. principal = the caller; context.origin = the human.

// Caller grants. The action glob doc.* is the schema action group "doc.*".
@id("publish-agent-doc")
permit (principal == Agent::"publish-agent", action in Action::"doc.*", resource)
when { resource.path like "doc/*" };

@id("editors-doc")
permit (principal in Group::"editors", action in Action::"doc.*", resource)
when { resource.path like "doc/*" };

// The origin must itself hold a grant (P2).
@id("origin-has-no-grant")
forbid (principal, action, resource)
unless {
  context has origin && context.origin in Group::"editors" &&
  action in Action::"doc.*" && resource.path like "doc/*"
};

// Human -> agent edge: intake-agent acts_for group:editors on read, write and comment.
@id("no-acts-for-edge")
forbid (principal, action, resource)
when { context has first_agent }
unless {
  context has origin && context.first_agent == Agent::"intake-agent" &&
  context.origin in Group::"editors" &&
  action in [Action::"doc.read", Action::"doc.write", Action::"doc.comment"]
};

// Agent -> agent edges (may_delegate). context.hops is the chain's consecutive agent pairs,
// computed outside Cedar (README). Every hop must be an edge that lists the action.
@id("no-may-delegate-edge (read, comment)")
forbid (principal, action in [Action::"doc.read", Action::"doc.comment"], resource)
unless {
  ["intake-agent>summary-agent", "summary-agent>publish-agent"].containsAll(context.hops)
};

@id("no-may-delegate-edge (write)")
forbid (principal, action == Action::"doc.write", resource)
unless { ["summary-agent>publish-agent"].containsAll(context.hops) };

// delegation.max_depth: 3 (context.depth = len(chain) - 1, computed outside Cedar).
@id("max-depth")
forbid (principal, action, resource)
when { context.depth > 3 };
