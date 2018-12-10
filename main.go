package main

import (
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

var router *mux.Router
var listenPort string
var tenantsRegexp string
var basicAuthPrefixes string
var ipRegex = regexp.MustCompile(`^(.+?)(?::\d{0,5})?$`)

func init() {
	listenPort = os.Getenv("PORT")
	if len(listenPort) == 0 {
		log.Println("No port specified, using 8080 as default.")
		listenPort = "8080"
	}
	tenants := []string{}
	for tenant := range config.Tenants {
		tenants = append(tenants, tenant)
	}
	tenantsRegexp = "(?:" + strings.Join(tenants, "|") + ")"
	basicAuthPrefixes = "(?:" + regexp.MustCompile(` +`).ReplaceAllString(config.BasicAuthPrefixes, "|") + ")"
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	returnStatus(w, http.StatusOK, "OK")
}

func noAuthHandler(w http.ResponseWriter, r *http.Request) {
	returnStatus(w, http.StatusOK, "")
}

func returnStatus(w http.ResponseWriter, statusCode int, errorMsg string) {
	w.WriteHeader(statusCode)
	if errorMsg != "" {
		w.Write([]byte(errorMsg))
	}
}

func getTenant(r *http.Request) string {
	return mux.Vars(r)["tenant"]
}

func isWebSocket(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

func getCookiePath(r *http.Request) (string, error) {
	route := mux.CurrentRoute(r)
	vars := mux.Vars(r)
	url, err := route.URLPath("tenant", vars["tenant"], "prefix", vars["prefix"])
	if err != nil {
		log.Println(getUserIP(r), "Error retrieving route URL:", err.Error())
		return "", err
	}
	s := url.Path
	if !strings.HasSuffix(s, "/") {
		if idx := strings.LastIndex(s, "/"); idx != -1 && idx != len(s) {
			s = s[:idx+1]
		}
	}
	return s, nil
}

func getUserIP(r *http.Request) string {
	headerIP := r.Header.Get("X-Forwarded-For")
	if headerIP != "" {
		return headerIP
	}

	return ipRegex.FindStringSubmatch(r.RemoteAddr)[1]
}

func main() {
	router = mux.NewRouter()

	router.HandleFunc("/healthz", healthHandler).Methods(http.MethodGet)

	router.Path("/login/oidc").HandlerFunc(oidcHandler).Methods(http.MethodGet)

	basic := router.PathPrefix("/{prefix:" + basicAuthPrefixes + "}/{tenant:" + tenantsRegexp + "}/").Subrouter()
	basic.PathPrefix("/").HandlerFunc(ifLoggedIn(setClaims, basicAuthLogin))

	implicit := router.PathPrefix("/{tenant:" + tenantsRegexp + "}/").Subrouter()
	implicit.Path("/login").HandlerFunc(ifLoggedIn(setClaims, login)).Methods(http.MethodGet)
	implicit.Path("/logout").HandlerFunc(ifLoggedIn(logout, beginOIDCLogout)).Methods(http.MethodGet)
	implicit.PathPrefix("/").HandlerFunc(ifLoggedIn(setClaims, implicitFlowLogin))

	router.PathPrefix("/").HandlerFunc(noAuthHandler)

	var listenAddr = ":" + listenPort
	log.Println("Starting web server at", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, handlers.CORS()(router)))
}
