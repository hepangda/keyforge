// Package web embeds the React SPA bundle that lives under web/dist and
// exposes it to the rest of keyforge via NewSPA. The embed directive
// must live in this package because //go:embed paths are resolved
// relative to the .go file; the public consumer is internal/httpx/spa,
// which re-exports the Handler.
//
// Two URL prefixes mount the same single-page app:
//
//   /portal/*  — end-user portal
//   /admin/*   — admin console
//
// Both rely on HTML5 history routing, so any non-asset request must
// return index.html so the React Router can do its job. Static assets
// under /assets/* are served directly with long-lived cache headers
// (Vite stamps each filename with a content hash).
package web

import (
	"embed"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed dist
var bundle embed.FS

// Handler serves the SPA.
type Handler struct {
	root  fs.FS
	index []byte
}

// NewSPA constructs the Handler. Returns an error if the embed bundle is
// missing index.html (which happens when web/dist hasn't been built).
func NewSPA() (*Handler, error) {
	root, err := fs.Sub(bundle, "dist")
	if err != nil {
		return nil, err
	}
	f, err := root.Open("index.html")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	idx, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return &Handler{root: root, index: idx}, nil
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	clean := path.Clean(r.URL.Path)
	rel := strings.TrimPrefix(clean, "/")
	// Strip /portal or /admin prefixes so we look up files inside dist/.
	for _, pfx := range []string{"portal", "admin"} {
		if rel == pfx {
			rel = ""
			break
		}
		if strings.HasPrefix(rel, pfx+"/") {
			rel = strings.TrimPrefix(rel, pfx+"/")
			break
		}
	}
	if rel == "" {
		h.writeIndex(w)
		return
	}
	f, err := h.root.Open(rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			h.writeIndex(w)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if stat.IsDir() {
		h.writeIndex(w)
		return
	}
	// Vite stamps assets/* filenames with a content hash, so cache hard.
	if strings.HasPrefix(rel, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("Content-Type", mimeFor(rel))
	rsc, ok := f.(io.ReadSeeker)
	if !ok {
		_, _ = io.Copy(w, f)
		return
	}
	http.ServeContent(w, r, rel, stat.ModTime(), rsc)
}

func (h *Handler) writeIndex(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	_, _ = w.Write(h.index)
}

// mimeFor picks the response content type. We avoid mime.TypeByExtension
// because its results are OS-dependent (Alpine ships a different mime db
// than Linux desktops); a hand-rolled lookup keeps the binary
// deterministic.
func mimeFor(p string) string {
	switch {
	case strings.HasSuffix(p, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(p, ".js"), strings.HasSuffix(p, ".mjs"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(p, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(p, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(p, ".png"):
		return "image/png"
	case strings.HasSuffix(p, ".jpg"), strings.HasSuffix(p, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(p, ".webp"):
		return "image/webp"
	case strings.HasSuffix(p, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(p, ".woff"):
		return "font/woff"
	case strings.HasSuffix(p, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(p, ".json"), strings.HasSuffix(p, ".map"):
		return "application/json; charset=utf-8"
	}
	return "application/octet-stream"
}
