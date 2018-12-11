package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"os"
	"strings"

	"github.com/go-redis/redis"
)

// Config global configuration
type Config struct {
	ListenPort        int                      `json:"listen_port"`
	BasicAuthPrefixes string                   `json:"basic_auth_prefixes"`
	SigningKeyFile    string                   `json:"signing_key_file"`
	Tenants           map[string]*TenantConfig `json:"tenants"`
	Redis             *redis.Options           `json:"redis"`
}

// TenantConfig per tenant configuration
type TenantConfig struct {
	OIDCProvider             string                `json:"oidc_provider"`
	OAuth2Provider           *OAuth2ProviderConfig `json:"oauth2_provider"`
	RedirectPath             string                `json:"redirect_path"`
	ClientID                 string                `json:"client_id"`
	ClientSecret             string                `json:"client_secret"`
	OIDCScopes               string                `json:"oidc_scopes"`
	BrokenAuthHeaderProvider bool                  `json:"broken_auth_header_provider"`
	SkipClientIDCheck        bool                  `json:"skip_client_id_check"`
	UserPath                 string                `json:"user_path"`
	GroupsPath               string                `json:"groups_path"`
}

// OAuth2ProviderConfig oauth2 (non OIDC) provider configuration
type OAuth2ProviderConfig struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURL  string `json:"jwks_uri"`
}

const defaultRedirectPath = "/login/oidc"
const defaultUserPath = "preferred_username"
const defaultGroupsPath = "resource_access.{client_id}.roles"

var config Config
var redirectPaths []string
var oidcConfigMap = make(map[string]*oidcConfig)
var redisdb *redis.Client
var signingKey *rsa.PrivateKey
var nonceBytes = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func init() {

	// get configuration file name
	filename := os.Getenv("CONFIG_FILE")
	if len(filename) == 0 {
		filename = "./config.json"
	}

	// parse configuration file
	configFile, err := os.Open(filename)
	defer configFile.Close()
	if err != nil {
		log.Fatal("Error opening config file ", filename, " ", err.Error())
	}
	jsonParser := json.NewDecoder(configFile)
	err = jsonParser.Decode(&config)
	if err != nil {
		log.Fatal("Error decoding config file ", filename, " ", err.Error())
	}

	// set defaults and prepare per tenant OIDC configuration for lazy initialization
	if config.ListenPort == 0 {
		config.ListenPort = 8080
	}
	redirectPaths = make([]string, 0)
	for tenant, tenantConfig := range config.Tenants {
		if tenantConfig.RedirectPath == "" {
			tenantConfig.RedirectPath = defaultRedirectPath
		}
		var duplicate = false
		for i := range redirectPaths {
			if redirectPaths[i] == tenantConfig.RedirectPath {
				duplicate = true
			}
		}
		if !duplicate {
			redirectPaths = append(redirectPaths, tenantConfig.RedirectPath)
		}
		if tenantConfig.UserPath == "" {
			tenantConfig.UserPath = defaultUserPath
		}
		if tenantConfig.GroupsPath == "" {
			tenantConfig.GroupsPath = strings.Replace(defaultGroupsPath, "{client_id}", tenantConfig.ClientID, -1)
		}
		oidcConfigMap[tenant] = &oidcConfig{tenantConfig: tenantConfig}
	}

	// initialize Redis client
	if config.Redis != nil {
		redisdb = redis.NewClient(config.Redis)
		_, err := redisdb.Ping().Result()
		if err != nil {
			log.Fatal("Problem connecting to Redis: ", err.Error())
		}
	}

	// get signing key if must sign
	if config.SigningKeyFile != "" {
		bytes, err := ioutil.ReadFile(config.SigningKeyFile)
		if err == nil {
			signingKey, err = parsePrivateKey(bytes)
		}
		if err != nil {
			log.Fatal("Error retrieving signing key from file ", config.SigningKeyFile, " ", err.Error())
		}
	}
}

func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return rsa, nil
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

func signedNonce() string {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = nonceBytes[mathrand.Intn(len(nonceBytes))]
	}
	snonce := string(nonce)
	if signingKey != nil {
		signed, _ := signingKey.Sign(rand.Reader, nonce, crypto.Hash(0))
		snonce = snonce + "." + base64.StdEncoding.EncodeToString(signed)
	}
	return snonce
}
