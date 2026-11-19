# unknown-principal

A chain contains an actor that matches no principal in the policy set, either as the caller or as a relay in the middle. The request is DENY (P5, fail closed) even though the grant applies to every link. A single-link chain with the policy's `require_human_origin: false` isolates the unknown principal as the only reason.

Threat: none (tests semantics).
