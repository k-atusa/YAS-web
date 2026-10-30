package main

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"path"
	"strings"
	"time"

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

	r := chi.NewRouter()
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.CORS)
	r.Use(middleware.MaxBodyBytes(50 * 1024 * 1024))

	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		middleware.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Mount("/api/auth", routes.AuthRouter())
	r.Mount("/api/accounts", routes.AccountsRouter())
	r.Mount("/api/contacts", routes.ContactsRouter())
	r.Mount("/api/webauthn", routes.WebAuthnRouter())

	embeddedFS, err := webui.FS()
	if err != nil {
		log.Fatalf("Failed to load embedded frontend assets: %v", err)
	}
	embeddedFileServer := http.FileServer(http.FS(embeddedFS))

	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		cleanPath := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if cleanPath != "." && cleanPath != "" {
			if f, err := embeddedFS.Open(cleanPath); err == nil {
				stat, statErr := f.Stat()
				_ = f.Close()
				if statErr == nil && !stat.IsDir() {
					embeddedFileServer.ServeHTTP(w, r)
					return
				}
			}
		}

		serveEmbeddedIndexHTML(w, r, embeddedFS)
	})

	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Printf("Server (API + Embedded Frontend) listening on http://localhost:%d", cfg.Port)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func serveEmbeddedIndexHTML(w http.ResponseWriter, r *http.Request, fsys fs.FS) {
	f, err := fsys.Open("index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, "Failed to read index.html", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(data))
}
