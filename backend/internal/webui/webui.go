package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:static
var embeddedStatic embed.FS

func FS() (fs.FS, error) {
	return fs.Sub(embeddedStatic, "static")
}
