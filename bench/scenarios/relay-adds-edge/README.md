# relay-adds-edge

Using the payments example policy, `[alice, refund-agent]` is DENY because `refund-agent` has no `acts_for`, while `[alice, support-agent, refund-agent]` is ALLOW because the relay supplies both edges. Inserting an intermediary can raise the decision when it supplies a missing edge; the engine does not claim otherwise (P1 relay monotonicity covers only replacing an existing edge).

Threat: none (tests semantics).
