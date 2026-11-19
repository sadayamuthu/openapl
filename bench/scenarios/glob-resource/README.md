# glob-resource

Staff and the wiki agent may read anything under `docs/*`, and a deny covers `docs/hr/salaries*`. Paths under the wildcard are ALLOW, the denied path is DENY despite the grant, and a path outside the wildcard is DENY for lack of a grant.

Threat: none (tests semantics).
