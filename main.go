package main

import (
	"github.com/joho/godotenv"
	"github.com/scalekit-inc/scalekit-sdk-go"
	"log"
	"net/http"
	"os"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	mux := http.NewServeMux()
	environmentUrl := os.Getenv("SCALEKIT_ENV_URL")
	clientId := os.Getenv("SCALEKIT_CLIENT_ID")
	clientSecret := os.Getenv("SCALEKIT_CLIENT_SECRET")
	redirectUri := os.Getenv("AUTH_REDIRECT_URI")
	webhookSecret := os.Getenv("SCALEKIT_WEBHOOK_SECRET")
	host := os.Getenv("HOST")

	sc := scalekit.NewScalekitClient(
		environmentUrl,
		clientId,
		clientSecret,
	)
	auth := NewAuth(sc, host, redirectUri)
	webhook := NewWebhook(sc, webhookSecret)

	mux.Handle("/", http.FileServer(NewBuildServer()))
	mux.HandleFunc("POST /auth/login", auth.LoginHandler)
	mux.HandleFunc("GET /auth/callback", auth.CallbackHandler)
	mux.HandleFunc("GET /auth/me", auth.MeHandler)
	mux.HandleFunc("POST /auth/logout", auth.LogoutHandler)
	mux.HandleFunc("POST /webhook", webhook.handleWebhook)

	err = http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatal("Error starting server")
	}
}
