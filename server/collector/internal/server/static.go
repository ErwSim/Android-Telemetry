package server

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// newStaticHandler serves the console files with an SPA fallback: unknown
// paths without an extension get index.html (client-side routing); missing
// assets get a 404.
func newStaticHandler(fsys fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name != "" && name != "index.html" {
			if st, err := fs.Stat(fsys, name); err == nil && !st.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					// Vite emits content-hashed file names under assets/.
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-cache")
				}
				http.ServeFileFS(w, r, fsys, name)
				return
			}
			if path.Ext(name) != "" {
				http.Error(w, "404 not found", http.StatusNotFound)
				return
			}
		}
		index, err := fs.ReadFile(fsys, "index.html")
		if err != nil {
			http.Error(w, "console unavailable", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}
