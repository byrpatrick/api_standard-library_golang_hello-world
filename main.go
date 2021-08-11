package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

const (
	corsAllowedDomain = "http://localhost:4040"
	permClaim         = "permissions"
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

var (
	tenantKeys jwk.Set
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

func validateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		token := req.Context().Value("user").(*jwt.Token)
		if token == nil {
			fmt.Printf("failed to find token in context\n")
			rw.WriteHeader(http.StatusForbidden)
			sendMessage(rw, &message{http.StatusText(http.StatusForbidden)})
			return
		}
		mc := token.Claims.(jwt.MapClaims)
		if !mc.VerifyAudience(auth0Audience, true) {
			fmt.Printf("audience verification failed\n")
			rw.WriteHeader(http.StatusForbidden)
			sendMessage(rw, &message{http.StatusText(http.StatusForbidden)})
			return
		}
		next.ServeHTTP(rw, req)
	})
}

func hasPermission(next http.Handler, permission string) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		token := req.Context().Value("user").(*jwt.Token)
		if token == nil {
			fmt.Printf("failed to find token in context\n")
			rw.WriteHeader(http.StatusForbidden)
			sendMessage(rw, &message{http.StatusText(http.StatusForbidden)})
			return
		}
		if !tokenHasPermission(token, permission) {
			fmt.Printf("permission check failed\n")
			rw.WriteHeader(http.StatusForbidden)
			sendMessage(rw, &message{http.StatusText(http.StatusForbidden)})
			return
		}
		next.ServeHTTP(rw, req)
	})
}

func tokenHasPermission(token *jwt.Token, permission string) bool {
	claims := token.Claims.(jwt.MapClaims)
	tkPermissions, ok := claims[permClaim]
	if !ok {
		return false
	}
	tkPermList, ok := tkPermissions.([]interface{})
	if !ok {
		return false
	}
	for _, perm := range tkPermList {
		if perm == permission {
			return true
		}
	}
	return false
}

// fetchTenantKeys fetch and parse the tenant JSON Web Keys (JWK). The keys
// are used for JWT token validation during requests authorization.
func fetchTenantKeys() {
	set, err := jwk.Fetch(context.Background(),
		fmt.Sprintf("https://%s/.well-known/jwks.json", auth0Domain))
	if err != nil {
		log.Fatalf("failed to parse tenant json web keys: %s\n", err)
	}
	tenantKeys = set
}

func jwtHandler() func(h http.Handler) http.Handler {
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return getPublicKey(token.Header["kid"].(string))
		},
		SigningMethod: jwt.SigningMethodRS256,
	})
	return jwtMiddleware.Handler
}

func getPublicKey(kid string) (interface{}, error) {
	for it := tenantKeys.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)
		if key.KeyID() != kid {
			continue
		}
		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			log.Printf("failed to create public key: %s", err)
			return nil, err
		}
		return rawKey, nil
	}
	return nil, errors.New("no matching key found")
}

func main() {
	initConfig()
	fetchTenantKeys()

	authHandler := jwtHandler()

	router := http.NewServeMux()
	router.Handle("/", http.NotFoundHandler())
	router.Handle("/api/messages/public", http.HandlerFunc(publicApiHandler))
	router.Handle("/api/messages/protected", authHandler(validateToken(
		http.HandlerFunc(protectedApiHandler))))
	router.Handle("/api/messages/admin", authHandler(validateToken(hasPermission(
		http.HandlerFunc(adminApiHandler), "read:admin-messages"))))
	routerWithCORS := handleCORS(router)

	server := &http.Server{
		Addr:    ":6060",
		Handler: routerWithCORS,
	}

	log.Printf("API server listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
