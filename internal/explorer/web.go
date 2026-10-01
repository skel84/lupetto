package explorer

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
)

//go:embed all:web/templates all:web/static
var embeddedWeb embed.FS

// Renderer buffers execution so missing/broken templates produce a clean 500,
// rather than partial HTML or a falsely successful HTTP response.
type Renderer interface {
	Render(io.Writer, string, any) error
}
type TemplateRenderer struct{ templates *template.Template }

func NewTemplateRenderer(templates *template.Template) *TemplateRenderer {
	return &TemplateRenderer{templates: templates}
}
func (r *TemplateRenderer) Render(w io.Writer, name string, model any) error {
	if r == nil || r.templates == nil || r.templates.Lookup(name) == nil {
		return fmt.Errorf("Explorer template %q is missing; dashboard UI is not installed", name)
	}
	var output bytes.Buffer
	if err := r.templates.ExecuteTemplate(&output, name, model); err != nil {
		return err
	}
	_, err := w.Write(output.Bytes())
	return err
}
func embeddedRenderer() (Renderer, error) {
	files, err := fs.Glob(embeddedWeb, "web/templates/*.html")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return NewTemplateRenderer(nil), nil
	}
	templates, err := template.New("explorer").ParseFS(embeddedWeb, files...)
	if err != nil {
		return nil, fmt.Errorf("parse Explorer templates: %w", err)
	}
	return NewTemplateRenderer(templates), nil
}
func embeddedStatic() fs.FS {
	assets, _ := fs.Sub(embeddedWeb, "web/static")
	return assets
}
