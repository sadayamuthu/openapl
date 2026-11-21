# attenuation-3hop

A human, three agents and a final publish agent form a three-hop chain, and the `intake-agent -> summary-agent` edge lists read and comment but not write. An action that every edge names is ALLOW, while write is DENY at the middle edge even though both endpoints hold it (P1).

Threat: confused deputy (authority widening across hops).
