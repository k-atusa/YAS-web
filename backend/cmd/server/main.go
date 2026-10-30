package main

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"path"
	"strings"

	"yas-web-backend/internal/config"
	"yas-web-backend/internal/db"
	"yas-web-backend/internal/middleware"
	"yas-web-backend/internal/routes"
	"yas-web-backend/internal/webui"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

func main() {
	cfg := config.Load()

	if err := db.Connect(cfg.DBPath); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	r, err := newRouter()
	if err != nil {
		log.Fatalf("Failed to load embedded frontend assets: %v", err)
	}

	log.Printf("Server (API + Embedded Frontend) listening on http://localhost:%d", cfg.Port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// newRouter wires the API routes and the embedded single-page frontend.
// Frontend and API share one origin, so no CORS handling is needed.
func newRouter() (http.Handler, error) {
	static, err := webui.FS()
	if err != nil {
		return nil, err
	}
	files := http.FileServerFS(static)

	r := chi.NewRouter()
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.MaxBodyBytes(1 << 20)) // 1 MiB: only JSON payloads (keys, contacts)

	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		middleware.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Mount("/api/auth", routes.AuthRouter())
	r.Mount("/api/accounts", routes.AccountsRouter())
	r.Mount("/api/contacts", routes.ContactsRouter())
	r.Mount("/api/webauthn", routes.WebAuthnRouter())

	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		// Serve real files as-is; fall back to index.html for SPA routes.
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if st, err := fs.Stat(static, name); err == nil && !st.IsDir() {
			files.ServeHTTP(w, r)
			return
		}
		http.ServeFileFS(w, r, static, "index.html")
	})

	return r, nil
}
