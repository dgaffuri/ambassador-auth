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

	"github.com/go-redis/redis"
)

// Config global configuration
type Config struct {
	BasicAuthPrefixes string                  `json:"basic_auth_prefixes"`
	SigningKeyFile    string                  `json:"signing_key_file"`
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
var signingKey *rsa.PrivateKey
var nonceBytes = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

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
