package staticfiles

import _ "embed"

// AdminHTML is embedded into the binary for non-container deployments.
//
//go:embed admin.html
var AdminHTML []byte
