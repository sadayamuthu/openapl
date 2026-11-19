# bench/scenarios/attenuation-3hop/rego/policy.rego
# OpenAPL policy attenuation-3hop 1.0.0, in Rego. input is the request as data: input.chain is the
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

# Grants editors-doc and publish-agent-doc.
granted(link) if {
	in_group(link, "editors")
	matches("doc.*", input.action)
	matches("doc/*", input.resource)
}

granted(link) if {
	link.id == "publish-agent"
	matches("doc.*", input.action)
	matches("doc/*", input.resource)
}

# Edges. intake-agent acts_for group:editors; may_delegate intake -> summary (read, comment)
# and summary -> publish (read, write, comment).
edge(i) if {
	chain[i - 1].kind == "human"
	chain[i].id == "intake-agent"
	in_group(chain[i - 1], "editors")
	input.action in {"doc.read", "doc.write", "doc.comment"}
}

may_delegate := {
	"intake-agent": {"summary-agent": {"doc.read", "doc.comment"}},
	"summary-agent": {"publish-agent": {"doc.read", "doc.write", "doc.comment"}},
}

edge(i) if {
	chain[i - 1].kind != "human"
	input.action in may_delegate[chain[i - 1].id][chain[i].id]
}

default decision := "DENY"

decision := "ALLOW" if {
	edges_ok
	granted(origin)
	granted(caller)
	count(chain) - 1 <= 3 # delegation.max_depth
	origin.kind == "human" # require_human_origin (default)
}
