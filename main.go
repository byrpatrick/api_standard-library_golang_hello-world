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

func publicApiHandler(rw http.ResponseWriter, req *http.Request) {
	sendMessage(rw, req, publicMessage)
}

func protectedApiHandler(rw http.ResponseWriter, req *http.Request) {
	sendMessage(rw, req, protectedMessage)
}

func adminApiHandler(rw http.ResponseWriter, req *http.Request) {
	sendMessage(rw, req, adminMessage)
}

func sendMessage(rw http.ResponseWriter, req *http.Request, data *message) {
	if req.Method == http.MethodOptions {
		sendOptionsResponse(rw)
		return
	}
	headers := rw.Header()
	headers.Add("Content-Type", "application/json")
	headers.Add("Access-Control-Allow-Origin", corsAllowedDomain)
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

func sendOptionsResponse(rw http.ResponseWriter) {
	headers := rw.Header()
	headers.Add("Access-Control-Allow-Origin", corsAllowedDomain)
	headers.Add("Access-Control-Allow-Headers", "Authorization")
	rw.WriteHeader(http.StatusNoContent)
	if _, err := rw.Write(nil); err != nil {
		log.Print("http response (options) write error", err)
	}
}

func main() {
	router := http.NewServeMux()
	router.HandleFunc("/api/messages/public", publicApiHandler)
	router.HandleFunc("/api/messages/protected", protectedApiHandler)
	router.HandleFunc("/api/messages/admin", adminApiHandler)

	server := &http.Server{
		Addr:    ":6060",
		Handler: router,
	}

	log.Fatal(server.ListenAndServe())
}
