package docs

import _ "embed"

// OpenAPIYAML is the FESS Control API contract (OpenAPI 3.0).
//
//go:embed openapi.yaml
var OpenAPIYAML []byte
