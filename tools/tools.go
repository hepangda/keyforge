//go:build tools

// Package tools is a placeholder for build-time tool dependencies.
//
// keyforge invokes tools via "go run <pkg>@<version>" from the Makefile so
// they are fetched on demand without polluting the main module graph. If you
// prefer pinning, add blank imports here and run `go mod tidy`.
package tools
