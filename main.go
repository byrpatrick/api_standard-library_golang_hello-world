package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"gopkg.in/yaml.v3"
)

const (
	corsAllowedDomain = "http://localhost:4040"
	authHeader        = "Authorization"
	ctxTokenKey       = "Auth0Token"
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
		token, err := extractToken(req)
		if err != nil {
			fmt.Printf("failed to parse payload: %s\n", err)
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{err.Error()})
			return
		}
		if !containsValidAudience(token) {
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{"invalid audience"})
			return
		}
		ctxWithToken := context.WithValue(req.Context(), ctxTokenKey, token)
		next.ServeHTTP(rw, req.WithContext(ctxWithToken))
	})
}

func containsValidAudience(token jwt.Token) bool {
	for _, anAudience := range token.Audience() {
		if anAudience == auth0Audience {
			return true
		}
	}
	return false
}

// extractToken parses the Authorization HTTP header for valid JWT token and
// validates it with AUTH0 JWK keys
func extractToken(req *http.Request) (jwt.Token, error) {
	authorization := req.Header.Get(authHeader)
	if authorization == "" {
		return nil, errors.New("authorization header missing")
	}
	bearerAndToken := strings.Split(authorization, " ")
	if len(bearerAndToken) < 2 {
		return nil, errors.New("malformed authorization header: " + authorization)
	}
	return jwt.Parse([]byte(bearerAndToken[1]), jwt.WithKeySet(tenantKeys))
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

func exitWithError(message string) {
	fmt.Fprintf(os.Stderr, "%s\n\n", message)
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}

func loadEnvYAML() {
	// yaml configuration is expected in current working directory
	myWd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	envCfg := path.Join(myWd, yamlCfgFileName)
	_, err = os.Stat(envCfg)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return
	}
	cfgContents, err := ioutil.ReadFile(envCfg)
	if err != nil {
		log.Fatalf("error reading %s: %v ", yamlCfgFileName, err)
	}
	cfg := map[string]string{}
	err = yaml.Unmarshal(cfgContents, cfg)
	if err != nil {
		log.Fatalf("yaml unmarshal error: %v", err)
	}
	if val, found := cfg[domainYamlKey]; found {
		auth0Domain = val
	}
	if val, found := cfg[audienceYamlKey]; found {
		auth0Audience = val
	}
}

func parseArgs() {
	var argAudience, argDomain string
	flag.StringVar(&argAudience, "a",
		os.Getenv("AUTH0_AUDIENCE"), "Auth0 API identifier, as audience")
	flag.StringVar(&argDomain, "d",
		os.Getenv("AUTH0_DOMAIN"), "Auth0 API tenant domain")
	flag.Parse()
	if argAudience != "" {
		auth0Audience = argAudience
	}
	if argDomain != "" {
		auth0Domain = argDomain
	}
}

func initConfig() {
	loadEnvYAML()
	parseArgs()
	if auth0Audience == "" {
		exitWithError("Auth0 API identifier (as audience) missing")
	}
	if auth0Domain == "" {
		exitWithError("Auth0 API tenant domain missing")
	}
	fetchTenantKeys()
}

func main() {
	initConfig()

	router := http.NewServeMux()
	router.Handle("/", http.NotFoundHandler())
	router.Handle("/api/messages/public", http.HandlerFunc(publicApiHandler))
	router.Handle("/api/messages/protected", validateToken(http.HandlerFunc(protectedApiHandler)))
	router.Handle("/api/messages/admin", validateToken(http.HandlerFunc(adminApiHandler)))
	routerWithCORS := handleCORS(router)

	server := &http.Server{
		Addr:    ":6060",
		Handler: routerWithCORS,
	}

	log.Printf("API server listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
