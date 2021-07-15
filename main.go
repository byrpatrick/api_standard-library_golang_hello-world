package main

import (
	"encoding/json"
	"log"
	"net/http"
)

const corsAllowedDomain = "http://localhost:4040"

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

func main() {
	router := http.NewServeMux()
	router.Handle("/", http.NotFoundHandler())
	router.Handle("/api/messages/public", handleCORS(http.HandlerFunc(publicApiHandler)))
	router.Handle("/api/messages/protected", handleCORS(http.HandlerFunc(protectedApiHandler)))
	router.Handle("/api/messages/admin", handleCORS(http.HandlerFunc(adminApiHandler)))

	server := &http.Server{
		Addr:    ":6060",
		Handler: router,
	}

	log.Printf("API server listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
