package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/scalekit-inc/scalekit-sdk-go"
)

type UserStore struct {
	sync.Mutex
	users map[string]scalekit.User
}

type Auth struct {
	sc          scalekit.Scalekit
	redirectUrl string
	userStore   UserStore
	host        string
}

func NewAuth(sc scalekit.Scalekit, host, redirectUrl string) Auth {
	return Auth{
		sc:          sc,
		host:        host,
		redirectUrl: redirectUrl,
		userStore: UserStore{
			users: make(map[string]scalekit.User),
		},
	}
}

func (a *Auth) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ConnectionId   string `json:"connectionId"`
		OrganizationId string `json:"organizationId"`
		Email          string `json:"email"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	options := scalekit.AuthorizationUrlOptions{}
	if body.ConnectionId != "" {
		options.ConnectionId = body.ConnectionId
	}
	if body.OrganizationId != "" {
		options.OrganizationId = body.OrganizationId
	}
	if body.Email != "" {
		options.LoginHint = body.Email
	}
	url, err := a.sc.GetAuthorizationUrl(a.redirectUrl, options)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"url": url.String()})
}

func (a *Auth) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	err_description := r.URL.Query().Get("error_description")
	if err_description != "" {
		http.Error(w, err_description, http.StatusBadRequest)
		return
	}
	if idpInitiatedLogin := r.URL.Query().Get("idp_initiated_login"); idpInitiatedLogin != "" {
		claims, err := a.sc.GetIdpInitiatedLoginClaims(idpInitiatedLogin)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		options := scalekit.AuthorizationUrlOptions{
			ConnectionId:   claims.ConnectionID,
			OrganizationId: claims.OrganizationID,
			LoginHint:      claims.LoginHint,
		}
		authUrl, err := a.sc.GetAuthorizationUrl(a.redirectUrl, options)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authUrl.String(), http.StatusFound)
		return
	}
	if code == "" {
		http.Error(w, "code not found", http.StatusBadRequest)
		return
	}
	res, err := a.sc.AuthenticateWithCode(
		code,
		a.redirectUrl,
		scalekit.AuthenticationOptions{},
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	atc, err := a.sc.GetAccessTokenClaims(res.AccessToken)
	itc, err := a.sc.GetAccessTokenClaims(res.IdToken)
	fmt.Println(atc, itc)
	uidParts := strings.Split(res.User.Id, ";")
	uid := uidParts[len(uidParts)-1]
	a.userStore.Lock()
	defer a.userStore.Unlock()
	a.userStore.users[uid] = res.User
	http.SetCookie(w, &http.Cookie{
		Name:     "uid",
		Value:    uid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, a.host+"/profile", http.StatusFound)
}

func (a *Auth) MeHandler(w http.ResponseWriter, r *http.Request) {
	uid, err := r.Cookie("uid")
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	a.userStore.Lock()
	defer a.userStore.Unlock()
	user, ok := a.userStore.users[uid.Value]
	if !ok {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(user)
}

func (a *Auth) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "uid",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, a.host+"/", http.StatusFound)
}
