package main

import (
	"fmt"
	"strconv"
	"strings"
)

type accessTokenClaims struct {
	JTI    string
	Exp    int64
	User   string
	Groups []string
}

func GetClaims(rawClaims map[string]interface{}, config *TenantConfig) (*accessTokenClaims, error) {

	var claims = &accessTokenClaims{}
	var ok bool
	jti := getClaim(rawClaims, "jti")
	if jti == nil {
		return nil, fmt.Errorf("missing jti")
	}
	if claims.JTI, ok = jti.(string); !ok {
		return nil, fmt.Errorf("bad jti: %v", jti)
	}
	exp := getClaim(rawClaims, "exp")
	if exp != nil {
		var e float64
		e, ok = exp.(float64)
		if !ok {
			return nil, fmt.Errorf("bad exp: %v", exp)
		}
		claims.Exp = int64(e)
	}
	user := getClaim(rawClaims, config.UserPath)
	if user != nil {
		if claims.User, ok = user.(string); !ok {
			return nil, fmt.Errorf("bad %s: %v", config.UserPath, user)
		}
	}
	groups := getClaim(rawClaims, config.GroupsPath)
	if groups != nil {
		var g []interface{}
		g, ok = groups.([]interface{})
		if !ok {
			return nil, fmt.Errorf("bad %s: %v", config.GroupsPath, groups)
		}
		claims.Groups = make([]string, len(g))
		for i := range g {
			if claims.Groups[i], ok = g[i].(string); !ok {
				return nil, fmt.Errorf("bad group value %s[%d]: %v", config.GroupsPath, i, g[i])
			}
		}
	}
	return claims, nil
}

// GetClaim return the value of the attribute with the given path expressed in dot notation
func getClaim(claims map[string]interface{}, path string) interface{} {
	keys := strings.Split(path, ".")
	var value interface{} = claims
	for _, key := range keys {
		if value = get(key, value); value == nil {
			break
		}
	}
	return value
}

func get(key string, s interface{}) (v interface{}) {
	var ok bool
	switch s.(type) {
	case map[string]interface{}:
		if v, ok = s.(map[string]interface{})[key]; !ok {
			v = nil
		}
	case []interface{}:
		if i, err := strconv.ParseInt(key, 10, 64); err == nil {
			array := s.([]interface{})
			if int(i) < len(array) {
				v = array[i]
			} else {
				v = nil
			}
		}
	}
	return v
}
