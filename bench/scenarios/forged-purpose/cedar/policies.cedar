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

// Delegation edges: refund-agent acts_for group:support on payments.refund.
@id("no-acts-for-edge")
forbid (principal is Agent, action, resource)
unless {
  context has origin && principal == Agent::"refund-agent" &&
  context.origin in Group::"support" && action == Action::"payments.refund"
};

// No may_delegate edges: an agent caller must be the chain's only agent, so it is also the
// agent the human handed the work to (the acts_for edge above is checked on the caller).
@id("no-may-delegate-edge")
forbid (principal is Agent, action, resource)
unless { [principal].containsAll(context.agents) };
