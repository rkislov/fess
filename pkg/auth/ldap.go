package auth

import (
	"fmt"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

type LDAPResult struct {
	DN          string
	Username    string
	DisplayName string
	Email       string
}

func AuthenticateLDAP(cfg AuthSettings, username, password string) (LDAPResult, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return LDAPResult{}, fmt.Errorf("username and password required")
	}
	url := strings.TrimSpace(cfg.LDAPURL)
	if url == "" {
		return LDAPResult{}, fmt.Errorf("ldap_url is not configured")
	}
	conn, err := ldap.DialURL(url)
	if err != nil {
		return LDAPResult{}, fmt.Errorf("ldap dial: %w", err)
	}
	defer conn.Close()

	bindDN := strings.TrimSpace(cfg.LDAPBindDN)
	bindPass := cfg.LDAPBindPassword
	if bindDN != "" {
		if err := conn.Bind(bindDN, bindPass); err != nil {
			return LDAPResult{}, fmt.Errorf("ldap service bind: %w", err)
		}
	}

	filterTpl := strings.TrimSpace(cfg.LDAPUserFilter)
	if filterTpl == "" {
		filterTpl = "(sAMAccountName=%s)"
	}
	filter := fmt.Sprintf(filterTpl, ldap.EscapeFilter(username))
	base := strings.TrimSpace(cfg.LDAPBaseDN)
	if base == "" {
		return LDAPResult{}, fmt.Errorf("ldap_base_dn is not configured")
	}

	sr := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false, filter, []string{"dn", "cn", "mail", cfg.LDAPUserAttr}, nil)
	res, err := conn.Search(sr)
	if err != nil {
		return LDAPResult{}, fmt.Errorf("ldap search: %w", err)
	}
	if len(res.Entries) == 0 {
		return LDAPResult{}, fmt.Errorf("ldap user not found")
	}
	entry := res.Entries[0]
	userDN := entry.DN
	if err := conn.Bind(userDN, password); err != nil {
		return LDAPResult{}, fmt.Errorf("ldap bind user: %w", err)
	}

	attr := strings.TrimSpace(cfg.LDAPUserAttr)
	if attr == "" {
		attr = "sAMAccountName"
	}
	un := entry.GetAttributeValue(attr)
	if un == "" {
		un = username
	}
	display := entry.GetAttributeValue("cn")
	if display == "" {
		display = un
	}
	email := entry.GetAttributeValue("mail")
	return LDAPResult{DN: userDN, Username: un, DisplayName: display, Email: email}, nil
}
