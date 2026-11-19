// bench/scenarios/forged-purpose/cedar/policies.cedar
// OpenAPL policy forged-purpose 1.0.0. principal = the caller; context.origin = the human.
// context.purpose is the verified claim; context.attributes holds the tool arguments.

// Caller grants.
@id("refund-agent-refunds")
permit (principal == Agent::"refund-agent", action == Action::"payments.refund", resource)
when {
  resource.path like "order/*" &&
  context has purpose && context.purpose == "customer-refund"
};

@id("support-refunds")
permit (principal in Group::"support", action == Action::"payments.refund", resource)
when { resource.path like "order/*" };

// The origin must itself hold a grant (P2).
@id("origin-has-no-grant")
forbid (principal, action, resource)
unless {
  context has origin && context.origin in Group::"support" &&
  action == Action::"payments.refund" && resource.path like "order/*"
};

// Delegation edges: refund-agent acts_for group:support on payments.refund; no may_delegate.
@id("no-acts-for-edge")
forbid (principal, action, resource)
when { context has first_agent }
unless {
  context has origin && context.first_agent == Agent::"refund-agent" &&
  context.origin in Group::"support" && action == Action::"payments.refund"
};

@id("no-may-delegate-edge")
forbid (principal, action, resource)
when { !context.hops.isEmpty() };
