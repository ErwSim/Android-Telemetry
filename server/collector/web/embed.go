// Package web embeds the console files.
//
// The console (server/console, React + Vite) is built into web/dist/ by the
// Dockerfile or by hand (see README). web/dist/ is not versioned: when it is
// absent, the minimal page of web/fallback/ is served instead, so that
// `go build` works without Node.
package web

import (
	"embed"
	"io/fs"
)

// The "all:*" pattern matches whatever exists (fallback/ always, dist/ when
// built) without failing when dist/ is missing.
//
//go:embed all:*
var files embed.FS

// Console returns the embedded console files and whether they are the real
// build (true) or the fallback page (false).
func Console() (fs.FS, bool) {
	if _, err := fs.Stat(files, "dist/index.html"); err == nil {
		sub, err := fs.Sub(files, "dist")
		if err == nil {
			return sub, true
		}
	}
	sub, err := fs.Sub(files, "fallback")
	if err != nil {
		panic(err)
	}
	return sub, false
}
