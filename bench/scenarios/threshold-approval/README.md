# threshold-approval

A payments agent may pay up to 200 on its own, and above that its grant falls back to `require_approval(role:finance-lead)`. Amounts at or under 200 are ALLOW, larger amounts are REQUIRE_APPROVAL, and a missing amount is DENY because an erroring condition never offers approval.

Threat: none (tests semantics).
