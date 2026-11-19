# prompt-injected-escalation

A helpdesk agent is delegated `tickets.read`, and injected text makes it ask for `tickets.delete`, which the human could do but never handed to the agent. The request must be DENY because no edge names the tool.

Threat: prompt-injected escalation.
