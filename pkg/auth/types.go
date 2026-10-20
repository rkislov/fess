package auth

import "time"

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"

	ProviderLocal = "local"
	ProviderLDAP  = "ldap"
)

type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	DisplayName  string     `json:"display_name"`
	Email        string     `json:"email"`
	Role         string     `json:"role"`
	AuthProvider string     `json:"auth_provider"`
	LDAPDN       string     `json:"ldap_dn,omitempty"`
	Active       bool       `json:"active"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type AuthSettings struct {
	LocalAuthEnabled bool   `json:"local_auth_enabled"`
	LDAPEnabled      bool   `json:"ldap_enabled"`
	LDAPURL          string `json:"ldap_url"`
	LDAPBindDN       string `json:"ldap_bind_dn"`
	LDAPBindPassword string `json:"ldap_bind_password,omitempty"`
	LDAPBaseDN       string `json:"ldap_base_dn"`
	LDAPUserFilter   string `json:"ldap_user_filter"`
	LDAPUserAttr     string `json:"ldap_user_attr"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type Claims struct {
	UserID   string
	Username string
	Role     string
}
