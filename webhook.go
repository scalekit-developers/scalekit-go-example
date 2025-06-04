package main

import (
	"fmt"
	"github.com/scalekit-inc/scalekit-sdk-go"
	"io"
	"net/http"
)

type Webhook struct {
	webhookSecret string
	sc            scalekit.Scalekit
}

func NewWebhook(sc scalekit.Scalekit, webhookSecret string) *Webhook {
	return &Webhook{
		webhookSecret: webhookSecret,
		sc:            sc,
	}
}

func (wh *Webhook) handleWebhook(w http.ResponseWriter, r *http.Request) {
	fmt.Println("received web book")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	headers := map[string]string{
		"webhook-id":        r.Header.Get("webhook-id"),
		"webhook-signature": r.Header.Get("webhook-signature"),
		"webhook-timestamp": r.Header.Get("webhook-timestamp"),
	}
	_, err = wh.sc.VerifyWebhookPayload(wh.webhookSecret, headers, body)
	if err != nil {
		fmt.Println(err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	fmt.Println("received webhook payload and verified")
	w.WriteHeader(http.StatusOK)
}
