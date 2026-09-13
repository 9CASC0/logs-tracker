package api

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const (
	callerIdentityKey contextKey = "caller_identity"
	callerPermsKey    contextKey = "caller_permissions"
)

// Permission represents an authorized action within the audit system.
type Permission string

const (
	PermRecordRead       Permission = "record:read"
	PermRecordSearch     Permission = "record:search"
	PermBatchRead        Permission = "batch:read"
	PermVerificationRead Permission = "verification:read"
	PermConfigRead       Permission = "config:read"
	PermAlertAck         Permission = "alert:acknowledge"
)

// Pre-defined role permissions
var RolePermissions = map[string][]Permission{
	"admin": {
		PermRecordRead, PermRecordSearch, PermBatchRead,
		PermVerificationRead, PermConfigRead, PermAlertAck,
	},
	"app_service": {
		PermRecordRead, PermRecordSearch, PermVerificationRead,
	},
	"auditor": {
		PermRecordRead, PermRecordSearch, PermBatchRead,
		PermVerificationRead, PermConfigRead,
	},
	"verifier": {
		PermVerificationRead,
	},
}

// TokenValidator resolves an API token into a caller identity and permission set.
type TokenValidator interface {
	ValidateToken(token string) (caller string, perms []Permission, ok bool)
}

// StaticTokenValidator implements TokenValidator with configured tokens.
type StaticTokenValidator struct {
	tokens map[string][]Permission
}

// NewStaticTokenValidator creates a StaticTokenValidator.
func NewStaticTokenValidator(tokenMap map[string][]Permission) *StaticTokenValidator {
	return &StaticTokenValidator{tokens: tokenMap}
}

func (v *StaticTokenValidator) ValidateToken(token string) (string, []Permission, bool) {
	perms, ok := v.tokens[token]
	if !ok {
		return "", nil, false
	}
	return "service", perms, true
}

// RBACMiddleware checks if the caller holds the required permission for the endpoint.
func RBACMiddleware(required PermCheck, validator TokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing authorization header")
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			token = strings.TrimSpace(token)

			caller, perms, valid := validator.ValidateToken(token)
			if !valid {
				writeError(w, http.StatusForbidden, "FORBIDDEN", "Invalid token or insufficient credentials")
				return
			}

			if !hasPermission(perms, required.Permission) {
				writeError(w, http.StatusForbidden, "FORBIDDEN", "Access denied: missing permission "+string(required.Permission))
				return
			}

			ctx := context.WithValue(r.Context(), callerIdentityKey, caller)
			ctx = context.WithValue(ctx, callerPermsKey, perms)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// PermCheck defines permission requirements for a route.
type PermCheck struct {
	Permission Permission
}

func hasPermission(perms []Permission, required Permission) bool {
	for _, p := range perms {
		if p == required {
			return true
		}
	}
	return false
}
