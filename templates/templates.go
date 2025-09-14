package templates

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"birdhole/file"
	// Import the slices package (Go 1.21+)
)

//go:embed gallery.html detail.html welcome.html
var templateFS embed.FS

var (
	appTemplates *template.Template
	funcMap      = template.FuncMap{
		"formatDate":  formatDate,
		"formatBytes": formatBytes,
		"joinTags":    joinTags,
		// "truncate":    truncateString, // Removed - Helper exists in handlers pkg, not used directly in tmpl?
		"addQuery":         addQueryParam,
		"default":          defaultFunc,
		"isInList":         isInList,
		"buildQueryString": buildQueryString,
		"dict":             dictFunc,
		"upper":            strings.ToUpper,
		"trimSuffix":       strings.TrimSuffix,
	}
)

// Load parses the embedded templates.
func Load() error {
	var err error
	appTemplates = template.New("").Funcs(funcMap)
	appTemplates, err = appTemplates.ParseFS(templateFS, "*.html")
	if err != nil {
		return err
	}
	slog.Info("HTML templates loaded")
	return nil
}

// Get returns the parsed templates instance.
func Get() *template.Template {
	return appTemplates
}

// Render executes the named template with the given data.
func Render(w io.Writer, name string, data any) error {
	return appTemplates.ExecuteTemplate(w, name, data)
}

// --- Template Helper Functions ---

func formatDate(timestamp int64) string {
	if timestamp <= 0 {
		return "N/A"
	}
	return time.Unix(timestamp, 0).Format("Jan 2, 2006")
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func joinTags(tags []string) string {
	return strings.Join(tags, ", ")
}

// addQueryParam adds or replaces a query parameter in a URL string (relative or absolute).
func addQueryParam(rawURL string, key string, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL // Return original on error
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// defaultFunc returns the default value if the given value is considered empty/zero.
func defaultFunc(defaultValue interface{}, value interface{}) interface{} {
	if value == nil {
		return defaultValue
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String, reflect.Slice, reflect.Array, reflect.Map:
		if v.Len() == 0 {
			return defaultValue
		}
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return defaultValue
		}
	case reflect.Bool:
		if !v.Bool() {
			return defaultValue // Return default for false boolean values
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.Int() == 0 {
			return defaultValue // Return default for zero integer values
		}
		// Add other types (float, uint) if needed
	}
	return value
}

// isInList checks if a string item exists in a slice of strings.
func isInList(item string, list []string) bool {
	// Use slices.Contains for Go 1.21+
	return slices.Contains(list, item)
	// // Manual check for older Go versions:
	// for _, v := range list {
	// 	if v == item {
	// 		return true
	// 	}
	// }
	// return false
}

// buildQueryString creates a URL query string from given parameters.
// Returns template.URL to prevent double-encoding in HTML attributes.
func buildQueryString(params map[string]interface{}) template.URL {
	vals := url.Values{}
	for key, value := range params {
		switch v := value.(type) {
		case string:
			if v != "" {
				vals.Set(key, v)
			}
		case []string:
			// Add each non-empty string in the slice
			for _, item := range v {
				if item != "" {
					vals.Add(key, item)
				}
			}
			// Add other types like int if needed
		}
	}
	// Safe: URL parameters are properly encoded before conversion to template.URL
	return template.URL(vals.Encode()) // #nosec G203
}

// dictFunc creates a map from a list of key-value pairs.
func dictFunc(values ...interface{}) (map[string]interface{}, error) {
	if len(values)%2 != 0 {
		return nil, errors.New("dict requires an even number of arguments (key-value pairs)")
	}
	m := make(map[string]interface{}, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, errors.New("dict keys must be strings")
		}
		m[key] = values[i+1]
	}
	return m, nil
}

// FileInfoWrapper wraps FileInfo to potentially add extra fields for templates.
type FileInfoWrapper struct {
	file.Info
	Key             string        // Admin/Gallery key for constructing URLs
	Snippet         string        // For text file previews
	RenderedContent template.HTML // For markdown detail view
	IsAdmin         bool          // Added to control admin features in detail view
}
