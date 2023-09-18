// Package consts defines the constants used by the project
package consts

import log "github.com/sirupsen/logrus"

var (
	// Version is the version of the executable.
	Version = "Dev"
)

const (
	// TEXTDOMAIN is the gettext domain for l10n.
	TEXTDOMAIN = "adsys"

	// DefaultLogLevel is the default logging level selected without any option.
	DefaultLogLevel = log.DebugLevel

	// DefaultSocketPath is the default socket path.
	DefaultSocketPath = "/tmp/run/authd.sock"

	// DefaultCacheDir is the default directory for the cache.
	DefaultCacheDir = "/tmp/var/cache/authd/"

	// DefaultRunDir is the default run directory.
	DefaultRunDir = "/tmp/run/authd/"
)
