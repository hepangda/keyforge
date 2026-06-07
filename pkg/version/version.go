// Package version exposes build-time version metadata.
package version

// Version is the keyforge build version, set via -ldflags at compile time.
// Defaults to "dev" for unstamped local builds.
var Version = "dev"
