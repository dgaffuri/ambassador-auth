package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/go-redis/redis"
	"golang.org/x/oauth2"
)

type oidcConfig struct {
	init         sync.Once
	initErr      error
	tenantConfig TenantConfig
	config       *oidc.Config
	provider     *oidc.Provider
	oauth2Config oauth2.Config
	cookieDomain string
	cookieSecure bool
	logoutURL    string
}

type stateItem struct {
	Tenant      string    `json:"tenant"`
	CookiePath  string    `json:"path"`
	Destination string    `json:"dest"`
	Expiration  time.Time `json:"exp"`
}

type refreshToken struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Expiry   int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
}

type accessTokenClaims struct {
	JTI            string                            `json:"jti"`
	Exp            int64                             `json:"exp"`
	Username       string                            `json:"preferred_username"`
	ResourceAccess map[string]map[string]interface{} `json:"resource_access"`
}

var ctx context.Context
var oidcConfigMap = make(map[string]*oidcConfig)
var redisdb *redis.Client

func init() {

	// prepare per tenant OIDC configuration for lazy initialization
	ctx = context.Background()
	for tenant, tenantConfig := range config.Tenants {
		oidcConfigMap[tenant] = &oidcConfig{tenantConfig: tenantConfig}
	}

	rand.Seed(time.Now().UnixNano())

	if config.Redis != nil {
		redisdb = redis.NewClient(config.Redis)
		_, err := redisdb.Ping().Result()
		if err != nil {
			log.Fatal("Problem connecting to Redis: ", err.Error())
		}
	}
}

func initConfig(r *http.Request, oidcConfig *oidcConfig) error {

	tenant := getTenant(r)
	d, _ := httputil.DumpRequest(r, false)
	log.Println("Initializing", tenant, "OIDC config from request", "\n"+string(d))

	proto := r.Header.Get("x-forwarded-proto")
	if proto == "" {
		proto = "http"
	}

	tenantConfig := oidcConfig.tenantConfig

	oidcURL, err := url.ParseRequestURI(tenantConfig.OIDCProvider)
	if err != nil {
		return err
	}
	oidcConfig.provider, err = oidc.NewProvider(ctx, oidcURL.String())
	if err != nil {
		return err
	}

	oidcConfig.config = &oidc.Config{
		ClientID: tenantConfig.ClientID,
	}

	oidcConfig.oauth2Config = oauth2.Config{
		ClientID:     tenantConfig.ClientID,
		ClientSecret: tenantConfig.ClientSecret,
		Endpoint:     oidcConfig.provider.Endpoint(),
		RedirectURL:  proto + "://" + r.Host + "/login/oidc",
		Scopes:       append(strings.Split(tenantConfig.OIDCScopes, " "), oidc.ScopeOpenID),
	}

	oidcConfig.cookieDomain = strings.Split(r.Host, ":")[0]
	oidcConfig.cookieSecure = proto == "https"

	// not managed by oidc package
	oidcConfig.logoutURL, err = getLogoutURL(ctx, oidcURL.String())
	if err != nil {
		return err
	}

	log.Println(getUserIP(r), r.URL.String(), "initialized", tenant, "OIDC config with",
		"ClientID:", oidcConfig.oauth2Config.ClientID,
		"Endpoint:", oidcConfig.oauth2Config.Endpoint,
		"RedirectURL:", oidcConfig.oauth2Config.RedirectURL,
		"Scopes:", oidcConfig.oauth2Config.Scopes,
		"cookieDomain:", oidcConfig.cookieDomain,
		"cookieSecure:", oidcConfig.cookieSecure,
		"logoutURL:", oidcConfig.logoutURL)

	return nil
}

// from oidc.NewProvider
func getLogoutURL(ctx context.Context, issuer string) (string, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return "", err
	}
	resp, err := doRequest(ctx, req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", resp.Status, body)
	}

	var p map[string]interface{}
	err = unmarshalResp(resp, body, &p)
	if err != nil {
		return "", fmt.Errorf("oidc: failed to decode provider discovery object: %v", err)
	}

	if p["issuer"] != issuer {
		return "", fmt.Errorf("oidc: issuer did not match the issuer returned by provider, expected %q got %q", issuer, p["issuer"])
	}
	return p["end_session_endpoint"].(string), nil
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}

func unmarshalResp(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}

// from oidc.NewProvider

func getOIDCConfig(r *http.Request) (*oidcConfig, error) {

	// get from map
	tenant := getTenant(r)
	oidcConfig := oidcConfigMap[tenant]

	// initialize from first request
	oidcConfig.init.Do(func() {
		oidcConfig.initErr = initConfig(r, oidcConfig)
		if oidcConfig.initErr != nil {
			log.Println("Error initializing", tenant, "OIDC config:", oidcConfig.initErr.Error())
		}
	})

	if oidcConfig.initErr != nil {
		return nil, oidcConfig.initErr
	}
	return oidcConfig, nil
}

func ifLoggedIn(yes func(w http.ResponseWriter, r *http.Request, claims *accessTokenClaims), no func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// check for valid access token in cookie and try to refresh or call yes/no function
		url := r.URL.String()
		claims, err := parseCookie(r)
		if err != nil {
			if strings.Contains(err.Error(), "oidc: token is expired") {
				if doRefresh(w, r) {
					return
				}
				log.Println(getUserIP(r), url, "Token expired but can't refresh.")
			} else if !strings.Contains(err.Error(), "http: named cookie not present") {
				log.Println(getUserIP(r), url, "Problem parsing cookie:", err.Error(), ".")
			}
		} else {

			// logged in with signed access token
			log.Println(getUserIP(r), url, "Already logged in", claims.Username, ".")
			yes(w, r, claims)
			return
		}

		// not logged in
		no(w, r)
	}
}

func setClaims(w http.ResponseWriter, r *http.Request, claims *accessTokenClaims) {
	oidcConfig, _ := getOIDCConfig(r)
	w.Header().Set("X-Remote-User", claims.Username)
	roles := ""
	for _, role := range claims.ResourceAccess[oidcConfig.config.ClientID]["roles"].([]interface{}) {
		if roles == "" {
			roles = role.(string)
		} else {
			roles = roles + ";" + role.(string)
		}
	}
	w.Header().Set("X-Remote-Groups", roles)
	w.Header().Set("X-Tenant", getTenant(r))
	w.Header().Set("X-Trusted", "true")
	returnStatus(w, http.StatusOK, "")
}

func oidcHandler(w http.ResponseWriter, r *http.Request) {
	var authCode = r.FormValue("code")
	if len(authCode) == 0 {
		log.Println(getUserIP(r), "Missing url parameter: code")
		returnStatus(w, http.StatusBadRequest, "Missing url parameter: code")
		return
	}

	var state = r.FormValue("state")
	if len(state) == 0 {
		log.Println(getUserIP(r), "Missing url parameter: state")
		returnStatus(w, http.StatusBadRequest, "Missing url parameter: state")
		return
	}

	// Getting original destination from DB with state
	savedState, err := decodeState(state)
	if err != nil {
		log.Println(getUserIP(r), "Error decoding state", err.Error())
		returnStatus(w, http.StatusInternalServerError, "Error decoding state.")
		return
	}

	// cannot use getOIDCConfig here, because the request is not guaranteed to be per tenant
	// config have been already initialized anyway
	oidcConfig := oidcConfigMap[savedState.Tenant]

	oauth2Token, err := oidcConfig.oauth2Config.Exchange(ctx, authCode)
	if err != nil {
		log.Println(getUserIP(r), "Failed to exchange token:", err.Error())
		returnStatus(w, http.StatusInternalServerError, "Failed to exchange token.")
		return
	}

	_, err = getAccessToken(oauth2Token, oidcConfig)
	if err != nil {
		log.Println(getUserIP(r), err)
		returnStatus(w, http.StatusInternalServerError, err.Error())
		return
	}

	log.Println(getUserIP(r), savedState.Destination, "Login validated with token from Authorization Code Flow")
	addCookie(w, getUserIP(r), savedState.Destination, oauth2Token.AccessToken, savedState.CookiePath, oidcConfig.cookieDomain, oidcConfig.cookieSecure)
	http.Redirect(w, r, savedState.Destination, http.StatusFound)
}

func basicAuthLogin(w http.ResponseWriter, r *http.Request) {
	url := r.URL.String()
	username, password, ok := r.BasicAuth()
	if !ok {
		log.Println(getUserIP(r), url, "Missing basic auth")
		w.Header().Set("WWW-Authenticate", "Basic realm=Ambassador")
		returnStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	oidcConfig, err := getOIDCConfig(r)
	if err != nil {
		returnStatus(w, http.StatusBadRequest, "Failed to retrieve OIDC configuration.")
		return
	}
	oauth2Token, err := oidcConfig.oauth2Config.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		if rErr, ok := err.(*oauth2.RetrieveError); ok {
			if rErr.Response.StatusCode == http.StatusUnauthorized {
				log.Println(getUserIP(r), url, "Invalid basic auth")
				w.Header().Set("WWW-Authenticate", "Basic realm=Ambassador")
				returnStatus(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
		}
		log.Println(getUserIP(r), url, fmt.Errorf("unable to get token with password credentials: %v", err))
		returnStatus(w, http.StatusBadRequest, "unable to get token with password credentials")
		return
	}
	accessToken, err := getAccessToken(oauth2Token, oidcConfig)
	if err != nil {
		log.Println(getUserIP(r), url, err)
		returnStatus(w, http.StatusInternalServerError, err.Error())
		return
	}
	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
		var claims accessTokenClaims
		if err = accessToken.Claims(&claims); err != nil {
			log.Println(getUserIP(r), url, err)
			returnStatus(w, http.StatusUnauthorized, "Malformed access token.")
			return
		}
		log.Println(getUserIP(r), url, "Login validated with token from Resource Owner Password Credentials Grant, forwarding request")
		setClaims(w, r, &claims)
		return
	}
	cookiePath, err := getCookiePath(r)
	if err != nil {
		returnStatus(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Println(getUserIP(r), url, "Login validated with token from Resource Owner Password Credentials Grant, redirecting request")
	addCookie(w, getUserIP(r), url, oauth2Token.AccessToken, cookiePath, oidcConfig.cookieDomain, oidcConfig.cookieSecure)
	http.Redirect(w, r, url, http.StatusFound)
}

func implicitFlowLogin(w http.ResponseWriter, r *http.Request) {
	beginOIDCLogin(w, r, r.URL.String())
}

func doRefresh(w http.ResponseWriter, r *http.Request) bool {
	url := r.URL.String()
	cookie, err := r.Cookie("auth")
	if err != nil {
		return false
	}
	accessToken := cookie.Value
	if accessToken == "" {
		return false
	}
	dbKey := shasum(accessToken)
	refreshToken, err := redisdb.Get(dbKey).Result()
	if err != nil {
		log.Println(getUserIP(r), url, "Failed to retrieve refresh token for", dbKey, err.Error())
		return false
	}
	err = redisdb.Del(dbKey).Err()
	if err != nil {
		log.Println(getUserIP(r), url, "Failed to delete refresh token for", dbKey, err.Error())
	}
	oidcConfig, err := getOIDCConfig(r)
	if err != nil {
		log.Println(getUserIP(r), url, "Failed to retrieve OIDC configuration:", err.Error())
		return false
	}
	cookiePath, err := getCookiePath(r)
	if err != nil {
		log.Println(getUserIP(r), url, "Failed to retrieve cookie path:", err.Error())
		return false
	}

	// without AccessToken token is invalid, so refresh token will be used to obtain a new one
	token := &oauth2.Token{RefreshToken: refreshToken}
	oauth2Token, err := oidcConfig.oauth2Config.TokenSource(ctx, token).Token()
	if err != nil {
		log.Println(getUserIP(r), url, "Failed to refresh token:", err.Error())
		return false
	}

	_, err = getAccessToken(oauth2Token, oidcConfig)
	if err != nil {
		log.Println(getUserIP(r), err)
		returnStatus(w, http.StatusInternalServerError, err.Error())
		return false
	}

	log.Println(getUserIP(r), url, "Login validated with token from stored refresh token")
	addCookie(w, getUserIP(r), url, oauth2Token.AccessToken, cookiePath, oidcConfig.cookieDomain, oidcConfig.cookieSecure)
	http.Redirect(w, r, url, http.StatusFound)

	return true
}

func login(w http.ResponseWriter, r *http.Request) {
	beginOIDCLogin(w, r, "/")
}

func logout(w http.ResponseWriter, r *http.Request, claims *accessTokenClaims) {
	beginOIDCLogout(w, r)
}

func beginOIDCLogin(w http.ResponseWriter, r *http.Request, redirectURL string) {

	// encode tenant, cookie path and original URL in state and start login sequence
	cookiePath, err := getCookiePath(r)
	if err != nil {
		returnStatus(w, http.StatusInternalServerError, err.Error())
		return
	}
	state, err := encodeState(getTenant(r), cookiePath, redirectURL)
	if err != nil {
		log.Println(getUserIP(r), "Error saving state", state, "in DB:", err)
		returnStatus(w, http.StatusInternalServerError, "Error saving state in DB.")
		return
	}

	oidcConfig, err := getOIDCConfig(r)
	if err != nil {
		returnStatus(w, http.StatusBadRequest, "Failed to retrieve OIDC configuration.")
		return
	}

	log.Println(getUserIP(r), redirectURL, "Redirecting to IdP")
	http.Redirect(w, r, oidcConfig.oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func beginOIDCLogout(w http.ResponseWriter, r *http.Request) {
	oidcConfig, err := getOIDCConfig(r)
	if err != nil {
		returnStatus(w, http.StatusBadRequest, "Failed to retrieve OIDC configuration.")
		return
	}
	cookiePath, err := getCookiePath(r)
	if err == nil {
		expireCookie(w, r, cookiePath, oidcConfig.cookieDomain, oidcConfig.cookieSecure)
	}
	redirectURI := r.FormValue("return")
	if oidcConfig.logoutURL == "" {
		if redirectURI != "" {
			http.Redirect(w, r, redirectURI, http.StatusFound)
		} else {
			returnStatus(w, http.StatusOK, "")
		}
		return
	}
	realURL := oidcConfig.logoutURL
	if redirectURI != "" {
		realURL = realURL + "?redirect_uri=" + url.PathEscape(redirectURI)
	}
	http.Redirect(w, r, realURL, http.StatusFound)
}

func getAccessToken(oauth2Token *oauth2.Token, oidcConfig *oidcConfig) (*oidc.IDToken, error) {

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token field in OAuth 2.0 token")
	}

	// Verifying received ID token
	verifier := oidcConfig.provider.Verifier(oidcConfig.config)
	_, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("unable to verify ID token: %v", err)
	}
	accessToken, err := verifier.Verify(ctx, oauth2Token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("unable to verify Access token: %v", err)
	}

	// Save refresh token if any in redis
	if redisdb != nil && oauth2Token.RefreshToken != "" {

		refreshToken, err := parseRefreshToken(oauth2Token.RefreshToken)
		if err != nil {
			return nil, fmt.Errorf("unable to verify Refresh token: %v", err)
		}
		expiry := time.Duration(0)
		if refreshToken.Expiry > 0 {
			expiry = time.Until(time.Unix(refreshToken.Expiry, 0))
		}
		err = redisdb.Set(shasum(oauth2Token.AccessToken), oauth2Token.RefreshToken, expiry).Err()
		if err != nil {
			log.Println("unable to save Refresh token:", err)
		}
	}

	return accessToken, nil
}

func parseRefreshToken(p string) (*refreshToken, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	var token refreshToken
	err = json.Unmarshal(payload, &token)
	if err != nil {
		return nil, err
	}
	if token.Expiry > 0 {
		expiry := time.Unix(token.Expiry, 0)
		if time.Now().After(expiry) {
			return nil, fmt.Errorf("Expired token")
		}
	}
	return &token, nil
}

func addCookie(w http.ResponseWriter, ip string, url string, tokenString string, path string, domain string, secure bool) {
	log.Println(ip, url, "Setting cookie for domain", domain, "and path", path)
	cookie := &http.Cookie{
		Name:     "auth",
		Value:    tokenString,
		Path:     path,
		Domain:   domain,
		HttpOnly: true,
		Secure:   secure,
	}
	http.SetCookie(w, cookie)
}

func parseCookie(r *http.Request) (*accessTokenClaims, error) {
	var encoded string
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		encoded = header[7:]
	} else {
		cookie, err := r.Cookie("auth")
		if err != nil {
			return nil, err
		}
		encoded = cookie.Value
	}
	if len(encoded) == 0 {
		return nil, fmt.Errorf("Empty token")
	}
	var claims accessTokenClaims
	oidcConfig, err := getOIDCConfig(r)
	if err != nil {
		return nil, err
	}
	verifier := oidcConfig.provider.Verifier(oidcConfig.config)
	token, err := verifier.Verify(ctx, encoded)
	if err != nil {
		return nil, err
	}
	err = token.Claims(&claims)
	if err != nil {
		return nil, err
	}
	return &claims, nil
}

func expireCookie(w http.ResponseWriter, r *http.Request, path string, domain string, secure bool) {
	log.Println(getUserIP(r), r.URL.String(), "Expiring cookie for domain", domain, "and path", path)
	cookie := &http.Cookie{
		Name:     "auth",
		Value:    "",
		Expires:  time.Now().AddDate(0, 0, -2),
		Path:     path,
		Domain:   domain,
		HttpOnly: true,
		Secure:   secure,
	}
	http.SetCookie(w, cookie)
}

func encodeState(tenant string, cookiePath string, destination string) (string, error) {
	expiration := time.Now().Add(300 * time.Second)
	jsonItem, err := json.Marshal(&stateItem{Tenant: tenant, CookiePath: cookiePath, Destination: destination, Expiration: expiration})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonItem), nil
}

func decodeState(state string) (*stateItem, error) {
	var item stateItem
	jsonItem, err := base64.StdEncoding.DecodeString(state)
	if err == nil {
		err = json.Unmarshal([]byte(jsonItem), &item)
		if time.Now().After(item.Expiration) {
			err = fmt.Errorf("Expired state")
		}
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func shasum(s string) string {
	e := sha256.Sum256([]byte(s))
	return base64.StdEncoding.EncodeToString(e[:])
}
