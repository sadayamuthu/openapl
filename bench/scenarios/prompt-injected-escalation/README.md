# prompt-injected-escalation

A helpdesk agent is delegated only `tickets.read` by `acts_for`, but its own grant is over-broad (`tickets.*`, standing in for a tool binding) and the human may also delete tickets. Injected text makes it ask for `tickets.delete`, and the request is DENY solely because no delegation edge names the tool (the cases pin that no "has no grant" reason appears).

Threat: prompt-injected escalation.
