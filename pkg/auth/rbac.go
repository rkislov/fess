package auth

import "net/http"

func CanRead(role string) bool {
	return role == RoleAdmin || role == RoleOperator || role == RoleViewer
}

func CanWrite(role string) bool {
	return role == RoleAdmin || role == RoleOperator
}

func CanAdmin(role string) bool {
	return role == RoleAdmin
}

func RequireRole(w http.ResponseWriter, role string, allowed ...string) bool {
	for _, a := range allowed {
		if role == a {
			return true
		}
	}
	return false
}
