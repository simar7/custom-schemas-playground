package user.kubernetes.ID001

__rego_metadata__ := {
	"id": "ID001",
	"title": "Application not allowed",
	"severity": "HIGH",
	"type": "Kubernetes Custom Check",
	"description": "Applications are not allowed because of some reasons.",
}

__rego_input__ := {"selector": [{"type": "kubernetes"}]}

deny[msg] {
	input.kind == "Application"
	msg = sprintf("Found Application '%s' but Applications are not allowed", [input.metadata.name])
}
