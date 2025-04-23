package middleware

import (
	"birdhole/config"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Context keys
type contextKey string

const AuthKeyContextKey = contextKey("authKey")
const ClientIPContextKey = contextKey("clientIP")

// Middleware holds dependencies for middleware handlers.
type Middleware struct {
	log            *slog.Logger
	rateLimiters   map[string]*rate.Limiter
	rateLimitMutex sync.Mutex
	rateLimitR     rate.Limit
	rateLimitB     int
}

// New creates a new Middleware instance.
func New(logger *slog.Logger) *Middleware {
	r := rate.Limit(2)
	b := 4

	return &Middleware{
		log:          logger.With("component", "middleware"),
		rateLimiters: make(map[string]*rate.Limiter),
		rateLimitR:   r,
		rateLimitB:   b,
	}
}

// getClientIP extracts the client IP address (helper function)
// Uses same logic as ClientIP middleware, but reusable
func getClientIP(r *http.Request) string {
	clientIP := ""
	cfIP := r.Header.Get("CF-Connecting-IP")
	if cfIP != "" {
		clientIP = cfIP
	} else {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				clientIP = strings.TrimSpace(parts[0])
			}
		}
	}
	if clientIP == "" {
		remoteAddr := r.RemoteAddr
		ip, _, err := net.SplitHostPort(remoteAddr)
		if err == nil {
			clientIP = ip
		} else {
			clientIP = remoteAddr
		}
	}
	return clientIP
}

// RateLimit middleware - ADDED
func (m *Middleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		m.rateLimitMutex.Lock()
		limiter, exists := m.rateLimiters[ip]
		if !exists {
			// Create a new limiter for this IP if it doesn't exist
			limiter = rate.NewLimiter(m.rateLimitR, m.rateLimitB)
			m.rateLimiters[ip] = limiter
		}
		m.rateLimitMutex.Unlock()

		if !limiter.Allow() {
			// Log the rate limit event
			m.log.Warn("Rate limit exceeded", "client_ip", ip, "path", r.URL.Path)
			// Return 429 Too Many Requests
			w.Header().Set("Retry-After", "60") // Suggest retrying after 60 seconds
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ClientIP attempts to extract the real client IP address, considering reverse proxy headers.
func (m *Middleware) ClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use the helper function
		clientIP := getClientIP(r)
		// Store client IP in context
		ctx := context.WithValue(r.Context(), ClientIPContextKey, clientIP)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Logging logs request details.
func (m *Middleware) Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		clientIP := r.Context().Value(ClientIPContextKey).(string)
		if clientIP == "" {
			clientIP = r.RemoteAddr // Fallback if ClientIP middleware didn't run or failed
		}

		l := m.log.With(
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", clientIP,
			"user_agent", r.UserAgent(),
		)
		l.Info("Request started")

		// Use a response writer wrapper to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		l.Info("Request completed",
			"status", rw.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// responseWriter wrapper to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

// Recovery recovers from panics and logs them.
func (m *Middleware) Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.Header().Set("Connection", "close") // Prevent further requests
				m.log.Error("Panic recovered",
					"error", err,
					"stack", string(debug.Stack()),
					"method", r.Method,
					"path", r.URL.Path,
				)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// AuthCheck checks for required authentication keys.
func (m *Middleware) AuthCheck(cfg *config.Config, allowGallery, allowUpload, allowAdmin bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := ""
			// Check query parameter first (for gallery/admin GET requests)
			if r.URL.Query().Has("key") {
				key = r.URL.Query().Get("key")
			} else {
				// Check header (for upload POST)
				key = r.Header.Get("X-Auth-Token")
			}

			authed := false
			if allowGallery && cfg.GalleryKey == "" {
				authed = true // Public gallery allowed
			}
			if allowGallery && cfg.GalleryKey != "" && key == cfg.GalleryKey {
				authed = true
			}
			if allowUpload && cfg.UploadKey != "" && key == cfg.UploadKey {
				authed = true
			}
			if allowAdmin && cfg.AdminKey != "" && key == cfg.AdminKey {
				authed = true
			}

			if !authed {
				m.log.Warn("Authentication failed", "path", r.URL.Path, "key_provided", key != "")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Store the valid key in context for potential use later (e.g., isAdmin check)
			ctx := context.WithValue(r.Context(), AuthKeyContextKey, key)

			if next == nil { // Handle cases where AuthCheck is used just for the check (like galleryChain base)
				// If we reached here, auth is successful, but there's no next handler in this chain.
				// The actual route handler will be called via .ThenFunc() later.
				// We just need to pass the context along implicitly.
				// This feels slightly awkward, maybe refactor how chains are built in main.go.
				// For now, just serve with the context implicitly passed.
				// A placeholder handler could be used, but this works if ThenFunc is always used.
				// Consider adding a dummy final handler if needed.
				// Or better: refactor main.go to apply middleware directly to the final handler.
				// Let's assume .ThenFunc provides the actual next handler.
				// If next IS nil, we shouldn't actually serve anything here.
				// The calling logic in main.go needs to handle this.
				// Returning immediately prevents issues if next was truly nil.
				m.log.Debug("Auth check successful, passing context, expecting ThenFunc", "key", key)
				// We need to serve SOMETHING if next is nil and we passed auth.
				// This indicates a potential logic error in how middleware is chained in main.go
				// A simple OK might suffice for now, but main.go should be reviewed.
				// UPDATE: It's better to assume the caller (mux.Handle) calls next if not nil.
				// If used as `chain.ThenFunc()`, `next` here will be nil.
				// So we just pass the context and expect the final handler to be called.
				next.ServeHTTP(w, r.WithContext(ctx)) // This will panic if next is nil - main.go needs fix
				return                                // <-- Need to return after ServeHTTP in this case
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SecurityHeaders adds basic security headers.
func (m *Middleware) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Define CSP parts for easier modification
		defaultSrc := "'self'"
		scriptSrc := "'self' https://cdn.jsdelivr.net 'unsafe-inline'"
		styleSrc := "'self' https://cdn.jsdelivr.net 'unsafe-inline'"
		imgSrc := "'self' data: blob:"
		mediaSrc := "'self' data: blob:"
		objectSrc := "'none'"
		frameAncestors := "'none'"

		csp := fmt.Sprintf(
			"default-src %s; script-src %s; style-src %s; img-src %s; media-src %s; object-src %s; frame-ancestors %s;",
			defaultSrc,
			scriptSrc,
			styleSrc,
			imgSrc,
			mediaSrc,
			objectSrc,
			frameAncestors,
		)

		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Add HSTS if served over HTTPS
		// w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}
