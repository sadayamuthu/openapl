# confused-deputy

A staff member without the `finance` group sends a request through an export agent that itself holds `data.export`. The decision must be DENY because the origin lacks the action (P2), even though the agent holds it.

Threat: confused deputy.
