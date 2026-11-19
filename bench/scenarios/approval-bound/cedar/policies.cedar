// bench/scenarios/approval-bound/cedar/policies.cedar
// OpenAPL policy approval-bound 1.0.0. principal = the caller; context.origin = the human.
// Cedar has ALLOW and DENY only. A permit whose @id starts with "needs-approval:" marks the
// approval path (OpenAPL `otherwise`); the runner reports an ALLOW determined only by such
// permits as REQUIRE_APPROVAL.

// Caller grants.
@id("finance-pay")
permit (principal in Group::"finance", action == Action::"payments.pay", resource)
when { resource.path like "payment/*" };

@id("payment-small")
permit (principal is Agent, action == Action::"payments.pay", resource)
when {
  [Agent::"payments-agent", Agent::"other-agent"].contains(principal) &&
  resource.path like "payment/*" &&
  context.attributes has amount && context.attributes.amount <= 200
};

// payment-small's `when` is false: granted by a bound, unexpired approval item.
// attributes_hash and each item's `expired` flag are computed outside Cedar (README).
@id("payment-small (approved)")
permit (principal is Agent, action == Action::"payments.pay", resource)
when {
  [Agent::"payments-agent", Agent::"other-agent"].contains(principal) &&
  resource.path like "payment/*" &&
  context.attributes has amount && context.attributes.amount > 200 &&
  context has origin &&
  context.approvals.contains({
    entitlement_id: "payment-small", approver: "role:finance-lead",
    action: "payments.pay", resource: resource.path,
    attributes_hash: context.attributes_hash,
    origin: context.origin, caller: principal, expired: false
  })
};

// payment-small's `when` is false: eligible for approval by role:finance-lead.
@id("needs-approval:payment-small")
@approvers("role:finance-lead")
permit (principal is Agent, action == Action::"payments.pay", resource)
when {
  [Agent::"payments-agent", Agent::"other-agent"].contains(principal) &&
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

// Delegation edges: both agents act_for group:finance on payments.pay; no may_delegate.
@id("no-acts-for-edge")
forbid (principal, action, resource)
when { context has first_agent }
unless {
  context has origin &&
  [Agent::"payments-agent", Agent::"other-agent"].contains(context.first_agent) &&
  context.origin in Group::"finance" && action == Action::"payments.pay"
};

@id("no-may-delegate-edge")
forbid (principal, action, resource)
when { !context.hops.isEmpty() };
