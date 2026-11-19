// bench/scenarios/expired-task-grant/cedar/policies.cedar
// OpenAPL policy expiring-grants 1.0.0. principal = the caller; context.origin = the human.
// purpose, task_id and iat are the verified claims, passed in context; now is the decision time.

// Caller grants.
@id("agent-run-for-task")
permit (principal == Agent::"report-agent", action == Action::"report.run", resource)
when {
  resource.path like "report/*" &&
  context has purpose && context.purpose == "quarterly-report" &&  // purpose
  context has task_id                                                // expires: task
};

@id("agent-export-15m")
permit (principal == Agent::"report-agent", action == Action::"report.export", resource)
when {
  resource.path like "report/*" &&
  context has iat && context.iat <= context.now &&                   // expires: 15m
  context.now - context.iat <= 900
};

@id("analysts-reports")
permit (principal in Group::"analysts", action in Action::"report.*", resource)
when { resource.path like "report/*" };

// The origin must itself hold a grant (P2).
@id("origin-has-no-grant")
forbid (principal, action, resource)
unless {
  context has origin && context.origin in Group::"analysts" &&
  action in Action::"report.*" && resource.path like "report/*"
};

// Delegation edges: report-agent acts_for group:analysts on run and export.
@id("no-acts-for-edge")
forbid (principal is Agent, action, resource)
unless {
  context has origin && principal == Agent::"report-agent" &&
  context.origin in Group::"analysts" &&
  action in [Action::"report.run", Action::"report.export"]
};

// No may_delegate edges: an agent caller must be the chain's only agent, so it is also the
// agent the human handed the work to (the acts_for edge above is checked on the caller).
@id("no-may-delegate-edge")
forbid (principal is Agent, action, resource)
unless { [principal].containsAll(context.agents) };
