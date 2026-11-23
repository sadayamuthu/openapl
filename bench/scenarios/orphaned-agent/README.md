# orphaned-agent

A report agent is owned by `priya@acme.com`, and the decision uses a directory snapshot listing the active owners. When the owner is absent from the snapshot the agent is orphaned and every request through it is DENY.

Threat: orphaned agent.
