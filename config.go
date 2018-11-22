package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/go-redis/redis"
)

// Config global configuration
type Config struct {
	BasicAuthPrefixes string                  `json:"basic_auth_prefixes"`
	Tenants           map[string]TenantConfig `json:"tenants"`
	Redis             *redis.Options          `json:"redis"`
}

// TenantConfig per tenant configuration
type TenantConfig struct {
	OIDCProvider string `json:"oidc_provider"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	OIDCScopes   string `json:"oidc_scopes"`
}

var config Config

func init() {

	filename := os.Getenv("CONFIG_FILE")
	if len(filename) == 0 {
		filename = "./config.json"
	}

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
}
