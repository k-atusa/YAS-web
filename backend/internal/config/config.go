package config

import (
	"bufio"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port      int
	DBPath    string
	JWTSecret string
	Domain    string // WebAuthn relying-party ID (bare host name)
}

var App Config

func Load() Config {
	loadDotEnv(".env")
	loadDotEnv("../.env") // when started from backend/ via `go run`

	port := 4000
	if p, err := strconv.Atoi(os.Getenv("PORT")); err == nil && p > 0 {
		port = p
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Println("JWT_SECRET is not set; using insecure dev fallback. Set JWT_SECRET in production.")
		jwtSecret = "dev-secret"
	}

	domain := cleanDomain(os.Getenv("DOMAIN"))
	if domain == "" {
		domain = "localhost"
	}

	App = Config{
		Port:      port,
		DBPath:    "./data/yas-web.db",
		JWTSecret: jwtSecret,
		Domain:    domain,
	}
	return App
}

// cleanDomain accepts sloppy input like "https://example.com:4000/" and returns "example.com".
func cleanDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	if idx := strings.Index(d, "/"); idx != -1 {
		d = d[:idx]
	}
	if host, _, err := net.SplitHostPort(d); err == nil {
		d = host
	}
	return d
}

func loadDotEnv(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if key != "" && os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
}
