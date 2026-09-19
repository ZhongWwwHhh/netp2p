// Command netp2p-mockidp runs the in-process OIDC provider for the Docker
// end-to-end stack. It auto-approves device flows so tests do not need a human
// to complete the browser step.
package main

import (
	"flag"
	"log"
	"strings"

	"github.com/netp2p/netp2p/internal/oidctest"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:9999", "HTTP listen address")
	issuer := flag.String("issuer", "", "advertised issuer URL (defaults to the listen address)")
	subject := flag.String("subject", "sso-user-1", "subject of the auto-approved user")
	email := flag.String("email", "sso-user@example.com", "email claim")
	name := flag.String("name", "SSO User", "name claim")
	groups := flag.String("groups", "netp2p-admins", "comma separated groups claim")
	groupsClaim := flag.String("groups-claim", "groups", "claim name carrying groups")
	webSubject := flag.String("web-subject", "sso-web-user", "subject of the browser PKCE user")
	webGroups := flag.String("web-groups", "eng", "comma separated groups for the browser PKCE user")
	flag.Parse()

	user := &oidctest.User{Subject: *subject, Email: *email, Name: *name, Groups: splitGroups(*groups)}
	webUser := &oidctest.User{
		Subject: *webSubject, Email: *webSubject + "@example.com", Name: "SSO Web User",
		Groups: splitGroups(*webGroups),
	}
	server, err := oidctest.New(*listen, oidctest.Options{
		Issuer: *issuer, AutoApprove: true, Default: user, WebUser: webUser, GroupsClaim: *groupsClaim,
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("mock idp listening on %s with issuer %s for subject %s groups %v", *listen, server.Issuer, *subject, user.Groups)
	select {}
}

func splitGroups(value string) []string {
	result := make([]string, 0, 4)
	for _, group := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(group); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
