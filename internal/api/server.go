package api

import (
	"net/http"
	"strings"
)

// Server sets up HTTP routing for both internal API and public verification endpoints.
type Server struct {
	handler   *Handler
	validator TokenValidator
	mux       *http.ServeMux
}

// NewServer builds and configures the HTTP multiplexer.
func NewServer(h *Handler, validator TokenValidator) *Server {
	s := &Server{
		handler:   h,
		validator: validator,
		mux:       http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// Handler returns the http.Handler for the server.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) registerRoutes() {
	// Health check (unauthenticated)
	s.mux.HandleFunc("/health", s.handler.HealthHandler)

	// Public Verification Feed (unauthenticated, decoupled from internal auth)
	s.mux.HandleFunc("/public/verification/keys", s.handler.PublicKeysHandler)
	s.mux.HandleFunc("/public/verification/roots", s.handler.PublicRootsHandler)
	s.mux.HandleFunc("/public/verification/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
			return
		}
		s.handler.PublicVerifyProofHandler(w, r)
	})

	// Internal Read API (Protected with RBAC Middleware)
	s.mux.HandleFunc("/audit/records", s.wrapRBAC(PermCheck{Permission: PermRecordRead}, s.handler.GetRecordsHandler))

	s.mux.HandleFunc("/audit/records/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/verify") {
			s.wrapRBAC(PermCheck{Permission: PermVerificationRead}, s.handler.VerifyRecordHandler)(w, r)
		} else {
			s.wrapRBAC(PermCheck{Permission: PermRecordRead}, s.handler.GetRecordDetailHandler)(w, r)
		}
	})

	s.mux.HandleFunc("/audit/batches/", s.wrapRBAC(PermCheck{Permission: PermBatchRead}, s.handler.GetBatchHandler))
	s.mux.HandleFunc("/audit/config", s.wrapRBAC(PermCheck{Permission: PermConfigRead}, s.handler.GetConfigHandler))
	s.mux.HandleFunc("/audit/alerts/", s.wrapRBAC(PermCheck{Permission: PermAlertAck}, s.handler.AcknowledgeAlertHandler))
}

func (s *Server) wrapRBAC(check PermCheck, handlerFunc http.HandlerFunc) http.HandlerFunc {
	middleware := RBACMiddleware(check, s.validator)
	return middleware(handlerFunc).(http.HandlerFunc)
}
