package config

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port         int
	DBPath       string
	CorsOrigin   string
	JWTSecret    string
	WebAuthnRPID string
	FrontendDist string
}

var App Config

func Load() Config {
	loadDotEnv(".env")
	loadDotEnv("backend/.env")

	port := 4000
	if p := os.Getenv("PORT"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			port = parsed
		}
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = os.Getenv("SQLITE_PATH")
	}
	if dbPath == "" {
		dbPath = "./data/yas-web.db"
	}

	corsOrigin := os.Getenv("CORS_ORIGIN")
	if corsOrigin == "" {
		corsOrigin = "*"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Println("JWT_SECRET is not set; using insecure dev fallback. Set JWT_SECRET in production.")
		jwtSecret = "dev-secret"
	}

	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = "localhost"
	}

	frontendDist := os.Getenv("FRONTEND_DIST")
	if frontendDist == "" {
		frontendDist = "./public"
	}

	App = Config{
		Port:         port,
		DBPath:       dbPath,
		CorsOrigin:   corsOrigin,
		JWTSecret:    jwtSecret,
		WebAuthnRPID: rpID,
		FrontendDist: frontendDist,
	}
	return App
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
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"'`)
		if key != "" && os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
}
