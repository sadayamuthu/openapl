# expired-task-grant

An agent holds one grant that lives only while a task id is present and another that lasts 15 minutes from the token's `iat`. Requests without the task id, with an old `iat`, with no `iat` or with a future `iat` are DENY, and the 900-second bound itself is inclusive.

Threat: expired task grant.
