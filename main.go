package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/auth0/go-jwt-middleware/validate/josev2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	corsAllowedDomain = "http://localhost:4040"
)

const (
	yamlCfgFileName = "env.yaml"
	domainYamlKey   = "auth0-domain"
	audienceYamlKey = "auth0-audience"
)

// variables required from user
var (
	auth0Audience string
	auth0Domain   string
)

type message struct {
	Message string `json:"message"`
}

var (
	publicMessage    = &message{"The API doesn't require an access token to share this message."}
	protectedMessage = &message{"The API successfully validated your access token."}
	adminMessage     = &message{"The API successfully recognized you as an admin."}
)

func publicApiHandler(rw http.ResponseWriter, _ *http.Request) {
	sendMessage(rw, publicMessage)
}

func protectedApiHandler(rw http.ResponseWriter, _ *http.Request) {
	sendMessage(rw, protectedMessage)
}

func adminApiHandler(rw http.ResponseWriter, _ *http.Request) {
	sendMessage(rw, adminMessage)
}

func sendMessage(rw http.ResponseWriter, data *message) {
	rw.Header().Add("Content-Type", "application/json")
	bytes, err := json.Marshal(data)
	if err != nil {
		log.Print("json conversion error", err)
		return
	}
	_, err = rw.Write(bytes)
	if err != nil {
		log.Print("http response write error", err)
	}
}

func handleCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		headers := rw.Header()
		// Allow-Origin header shall be part of ALL the responses
		headers.Add("Access-Control-Allow-Origin", corsAllowedDomain)
		if req.Method != http.MethodOptions {
			next.ServeHTTP(rw, req)
			return
		}
		// process an HTTP OPTIONS preflight request
		headers.Add("Access-Control-Allow-Headers", "Authorization")
		rw.WriteHeader(http.StatusNoContent)
		if _, err := rw.Write(nil); err != nil {
			log.Print("http response (options) write error", err)
		}
	})
}

func hasPermission(next http.Handler, permission string) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		token := req.Context().Value(jwtmiddleware.ContextKey{})
		if token == nil {
			fmt.Printf("failed to find token in context\n")
			rw.WriteHeader(http.StatusForbidden)
			sendMessage(rw, &message{http.StatusText(http.StatusForbidden)})
			return
		}
		uc := token.(*josev2.UserContext)
		pc := uc.CustomClaims.(*PermissionsClaim)
		permissionFound := false
		for _, perm := range pc.Permissions {
			if perm == permission {
				permissionFound = true
				break
			}
		}
		if !permissionFound {
			fmt.Printf("permission check failed\n")
			rw.WriteHeader(http.StatusForbidden)
			sendMessage(rw, &message{http.StatusText(http.StatusForbidden)})
			return
		}
		next.ServeHTTP(rw, req)
	})
}

type PermissionsClaim struct {
	Permissions []string `json:"permissions"`
}

func (pc *PermissionsClaim) Validate(_ context.Context) error {
	return nil // no validation required
}

func jwtHandler() func(h http.Handler) http.Handler {
	auth0DomainURL, err := url.Parse("https://" + auth0Domain)
	if err != nil {
		log.Fatal(err)
	}
	keyProvider := josev2.NewCachingJWKSProvider(*auth0DomainURL, 30*time.Minute)
	expectedClaimsFunc := func() jwt.Expected {
		return jwt.Expected{
			Audience: []string{auth0Audience},
		}
	}
	permissionClaimFunc := func() josev2.CustomClaims {
		return &PermissionsClaim{}
	}

	validator, err := josev2.New(
		keyProvider.KeyFunc,
		jose.RS256,
		josev2.WithExpectedClaims(expectedClaimsFunc),
		josev2.WithCustomClaims(permissionClaimFunc),
	)
	if err != nil {
		log.Fatal(err)
	}

	m := jwtmiddleware.New(validator.ValidateToken)
	return m.CheckJWT
}

func main() {
	initConfig()

	validateToken := jwtHandler()

	router := http.NewServeMux()
	router.Handle("/", http.NotFoundHandler())
	router.Handle("/api/messages/public", http.HandlerFunc(publicApiHandler))
	router.Handle("/api/messages/protected", validateToken(
		http.HandlerFunc(protectedApiHandler)))
	router.Handle("/api/messages/admin", validateToken(hasPermission(
		http.HandlerFunc(adminApiHandler), "read:admin-messages")))
	routerWithCORS := handleCORS(router)

	server := &http.Server{
		Addr:    ":6060",
		Handler: routerWithCORS,
	}

	log.Printf("API server listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
