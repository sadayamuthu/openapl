# bench/scenarios/glob-resource/rego/policy.rego
# OpenAPL policy glob-resource 1.0.0, in Rego. input is the request as data: input.chain is the
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

# Grants staff-read-docs and wiki-agent-read-docs.
granted(link) if {
	in_group(link, "staff")
	input.action == "docs.read"
	matches("docs/*", input.resource)
}

granted(link) if {
	link.id == "wiki-agent"
	input.action == "docs.read"
	matches("docs/*", input.resource)
}

# Edge: wiki-agent acts_for group:staff on docs.read. No may_delegate edges.
edge(i) if {
	chain[i - 1].kind == "human"
	chain[i].id == "wiki-agent"
	in_group(chain[i - 1], "staff")
	input.action == "docs.read"
}

# Deny no-salary-pages (grant_to "*": every link).
denied if {
	input.action == "docs.read"
	matches("docs/hr/salaries*", input.resource)
}

default decision := "DENY"

decision := "ALLOW" if {
	not denied
	edges_ok
	granted(origin)
	granted(caller)
	origin.kind == "human" # require_human_origin (default)
}
