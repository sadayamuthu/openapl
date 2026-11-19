# group-and-role

An agent acts for the `sre` group, and the origin's grant comes from the `oncall` role, so both claims are needed. Having only the group or only the role is DENY, and a single-string claim counts as a one-item list.

Threat: none (tests semantics).
