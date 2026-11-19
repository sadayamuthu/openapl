// bench/scenarios/relay-adds-edge/cedar/policies.cedar
// OpenAPL policy payments-access 1.2.0. principal = the caller; context.origin = the human.
// Cedar has ALLOW and DENY only. A permit whose @id starts with "needs-approval:" marks the
// approval path (OpenAPL `otherwise`); the runner reports an ALLOW determined only by such
// permits as REQUIRE_APPROVAL.

// Caller grants. refund-small-orders' resource "order/${request.order_id}" needs string
// concatenation, which Cedar lacks: context.derived.order_resource is "order/" + order_id,
// computed outside Cedar from cedar/derived.json and compared exactly (never as a pattern).
@id("refund-small-orders")
permit (principal == Agent::"refund-agent", action == Action::"payments.refund", resource)
when {
  context.derived has order_resource && resource.path == context.derived.order_resource &&
  context has purpose && context.purpose == "customer-refund" &&     // purpose
  context has task_id &&                                             // expires: task
  context.attributes has amount && context.attributes.amount <= 200 &&      // when[0]
  context has origin && context.origin in Group::"support-staff"            // when[1]
};

// refund-small-orders applies but its `when` is false: eligible for role:support-manager.
@id("needs-approval:refund-small-orders")
@approvers("role:support-manager")
permit (principal == Agent::"refund-agent", action == Action::"payments.refund", resource)
when {
  context.derived has order_resource && resource.path == context.derived.order_resource &&
  context has purpose && context.purpose == "customer-refund" &&
  context has task_id &&
  context.attributes has amount &&
  (context.attributes.amount > 200 ||
   (context has origin && !(context.origin in Group::"support-staff")))
};

// The same, granted by a bound, unexpired approval item (attributes_hash and `expired`
// computed outside Cedar).
@id("refund-small-orders (approved)")
permit (principal == Agent::"refund-agent", action == Action::"payments.refund", resource)
when {
  context.derived has order_resource && resource.path == context.derived.order_resource &&
  context has purpose && context.purpose == "customer-refund" &&
  context has task_id &&
  context.attributes has amount &&
  (context.attributes.amount > 200 ||
   (context has origin && !(context.origin in Group::"support-staff"))) &&
  context has origin &&
  context.approvals.contains({
    entitlement_id: "refund-small-orders", approver: "role:support-manager",
    action: "payments.refund", resource: resource.path,
    attributes_hash: context.attributes_hash,
    origin: context.origin, caller: Agent::"refund-agent", expired: false
  })
};

@id("support-staff-refunds")
permit (principal in Group::"support-staff", action == Action::"payments.refund", resource)
when { resource.path like "order/*" };

// The origin must itself hold a grant (P2). require_human_origin: context.origin is a User.
@id("origin-has-no-grant")
forbid (principal, action, resource)
unless {
  context has origin && context.origin in Group::"support-staff" &&
  action == Action::"payments.refund" && resource.path like "order/*"
};

// Human -> agent edge: support-agent acts_for group:support-staff on payments.refund.
@id("no-acts-for-edge")
forbid (principal, action, resource)
when { context has first_agent }
unless {
  context has origin && context.first_agent == Agent::"support-agent" &&
  context.origin in Group::"support-staff" && action == Action::"payments.refund"
};

// Agent -> agent edge support-agent -> refund-agent (context.hops computed outside Cedar).
@id("no-may-delegate-edge")
forbid (principal, action, resource)
unless {
  ["support-agent>refund-agent"].containsAll(context.hops) &&
  action == Action::"payments.refund"
};

// delegation.max_depth: 3 (context.depth computed outside Cedar).
@id("max-depth")
forbid (principal, action, resource)
when { context.depth > 3 };

// Denies (grant_to "*": every link). An absent account_status fires the deny (fail closed).
@id("no-refunds-on-closed-accounts")
forbid (principal, action == Action::"payments.refund", resource)
when { resource.path like "order/*" }
unless {
  context.attributes has account_status && context.attributes.account_status != "closed"
};

@id("no-bulk-refunds")
forbid (principal, action == Action::"payments.refund", resource)
when { resource.path like "order/bulk-*" };
