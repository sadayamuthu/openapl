# bench/scenarios/unknown-principal/rego/policy.rego
# OpenAPL policy unknown-principal 1.0.0, in Rego. input is the request as data: input.chain is the
# ordered list of {id, kind, claims} links (origin first, caller last); purpose, task_id,
# iat and approvals are the verified claims; now is the decision time.
# Query: data.openapl.decision.
package openapl

chain := input.chain

origin := chain[0]

caller := chain[count(chain) - 1]

# A group or role claim is a list, or a single string read as a one-item list (SPEC 5.2).
claim_values(link, name) := {v | some v in link.claims[name]} if is_array(link.claims[name])

claim_values(link, name) := {link.claims[name]} if is_string(link.claims[name])

in_group(link, g) if {
	link.kind == "human"
	g in claim_values(link, "groups")
}

# OpenAPL globs: `*` matches any run of characters, including "/" and "." (no delimiters).
matches(pattern, value) if glob.match(pattern, null, value)

# Every link after the origin is reached by a delegation edge that lists the action.
edge_ok(i) if i == 0

edge_ok(i) if edge(i)

edges_ok if {
	every i, _ in chain {
		edge_ok(i)
	}
}

principals := {"known-agent", "known-relay"}

# Grant everyone-reads (grant_to "*": every link).
granted(_) if {
	input.action == "notes.read"
	matches("note/*", input.resource)
}

# Edges: known-agent acts_for group:staff; known-agent -> known-relay.
edge(i) if {
	chain[i - 1].kind == "human"
	chain[i].id == "known-agent"
	in_group(chain[i - 1], "staff")
	input.action == "notes.read"
}

edge(i) if {
	chain[i - 1].id == "known-agent"
	chain[i].id == "known-relay"
	input.action == "notes.read"
}

# Every agent or service link must be a principal of this policy (P5).
unknown_principal if {
	some link in chain
	link.kind != "human"
	not link.id in principals
}

default decision := "DENY"

# require_human_origin: false, so an agent may be the origin.
decision := "ALLOW" if {
	not unknown_principal
	edges_ok
	granted(origin)
	granted(caller)
}
