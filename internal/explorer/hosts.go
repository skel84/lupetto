package explorer

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// A rule without a port permits that host at any port; a rule with a port
// requires that exact port. Never derive allowed names from request/proxy data.
type hostRule struct{ host, port string }

func parseAllowedHosts(values []string) ([]hostRule, error) {
	if len(values) == 0 {
		values = []string{"localhost", "127.0.0.1", "[::1]"}
	}
	rules := make([]hostRule, 0, len(values))
	for _, value := range values {
		rule, err := parseHostAuthority(value)
		if err != nil {
			return nil, fmt.Errorf("invalid --allowed-host %q: %w", value, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseHostAuthority(authority string) (hostRule, error) {
	var host, port string
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return hostRule{}, errors.New("expected bracketed IPv6 literal")
		}
		host = authority[1:end]
		if ip := net.ParseIP(host); ip == nil || !strings.Contains(host, ":") {
			return hostRule{}, errors.New("expected bracketed IPv6 literal")
		}
		if suffix := authority[end+1:]; suffix != "" {
			if !strings.HasPrefix(suffix, ":") || len(suffix) == 1 {
				return hostRule{}, errors.New("expected host or host:port")
			}
			port = suffix[1:]
		}
	} else {
		var hasPort bool
		host, port, hasPort = strings.Cut(authority, ":")
		if hasPort && port == "" {
			return hostRule{}, errors.New("port is empty")
		}
	}
	if port != "" {
		for _, c := range port {
			if c < '0' || c > '9' {
				return hostRule{}, errors.New("port must be numeric")
			}
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return hostRule{}, errors.New("port must be between 1 and 65535")
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		// Bare IPv6 is ambiguous with a port and is not a valid HTTP authority.
		if strings.Contains(host, ":") && !strings.HasPrefix(authority, "[") {
			return hostRule{}, errors.New("IPv6 must be bracketed")
		}
		host = ip.String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if len(host) == 0 || len(host) > 253 {
			return hostRule{}, errors.New("invalid hostname")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return hostRule{}, errors.New("invalid hostname")
			}
			for _, c := range label {
				if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
					return hostRule{}, errors.New("invalid hostname")
				}
			}
		}
	}
	return hostRule{host: host, port: port}, nil
}

func (s *Server) hostAllowed(authority string) bool {
	request, err := parseHostAuthority(authority)
	if err != nil {
		return false
	}
	for _, rule := range s.allowedHosts {
		if request.host == rule.host && (rule.port == "" || request.port == rule.port) {
			return true
		}
	}
	return false
}
