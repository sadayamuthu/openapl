// bench/scenarios/threshold-approval/cedar/policies.cedar
// OpenAPL policy threshold-approval 1.0.0. principal = the caller; context.origin = the human.
// Cedar has ALLOW and DENY only. A permit whose @id starts with "needs-approval:" marks the
// approval path (OpenAPL `otherwise`); the runner reports an ALLOW determined only by such
// permits as REQUIRE_APPROVAL.

// Caller grants.
@id("finance-pay")
permit (principal in Group::"finance", action == Action::"payments.pay", resource)
when { resource.path like "payment/*" };

@id("payment-small")
permit (principal == Agent::"payments-agent", action == Action::"payments.pay", resource)
when {
  resource.path like "payment/*" &&
  context.attributes has amount && context.attributes.amount <= 200
};

// payment-small's `when` is false: granted by a bound, unexpired approval item.
// attributes_hash and each item's `expired` flag are computed outside Cedar (README).
@id("payment-small (approved)")
permit (principal == Agent::"payments-agent", action == Action::"payments.pay", resource)
when {
  resource.path like "payment/*" &&
  context.attributes has amount && context.attributes.amount > 200 &&
  context has origin &&
  context.approvals.contains({
    entitlement_id: "payment-small", approver: "role:finance-lead",
    action: "payments.pay", resource: resource.path,
    attributes_hash: context.attributes_hash,
    origin: context.origin, caller: Agent::"payments-agent", expired: false
  })
};

// payment-small's `when` is false (amount present and over 200): eligible for approval.
// An absent amount makes neither permit apply, so the request is denied (no grant).
@id("needs-approval:payment-small")
@approvers("role:finance-lead")
permit (principal == Agent::"payments-agent", action == Action::"payments.pay", resource)
when {
  resource.path like "payment/*" &&
  context.attributes has amount && context.attributes.amount > 200
};

// The origin must itself hold a grant (P2).
@id("origin-has-no-grant")
forbid (principal, action, resource)
unless {
  context has origin && context.origin in Group::"finance" &&
  action == Action::"payments.pay" && resource.path like "payment/*"
};

// Delegation edges: payments-agent acts_for group:finance on payments.pay; no may_delegate.
@id("no-acts-for-edge")
forbid (principal, action, resource)
when { context has first_agent }
unless {
  context has origin && context.first_agent == Agent::"payments-agent" &&
  context.origin in Group::"finance" && action == Action::"payments.pay"
};

@id("no-may-delegate-edge")
forbid (principal, action, resource)
when { !context.hops.isEmpty() };
