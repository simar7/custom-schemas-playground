package main

import input

# METADATA
# schemas:
# - input: schema["argocd"]
# scope: rule

deny {
	input.FOO == "BAR"
   	input.kind == 1234
}
