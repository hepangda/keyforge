// Package spa is the public import for the SPA mount. It delegates to the
// embed.FS that lives under the web/ package (which needs to own the
// embed directive so the relative path to web/dist resolves).
package spa

import (
	"net/http"

	webspa "github.com/hepangda/keyforge/web"
)

// Handler returns an http.Handler that serves the SPA. See web.NewSPA.
type Handler = webspa.Handler

// New constructs the SPA handler.
func New() (*Handler, error) { return webspa.NewSPA() }

// Mount registers the SPA on the chi-style mux at the two canonical
// roots used by the React app.
func Mount(mux interface {
	Handle(pattern string, h http.Handler)
},
	h *Handler,
) {
	mux.Handle("/portal", h)
	mux.Handle("/portal/", h)
	mux.Handle("/admin", h)
	mux.Handle("/admin/", h)
	mux.Handle("/assets/", h)
}
