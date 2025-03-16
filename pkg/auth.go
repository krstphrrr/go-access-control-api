package auth
import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	// "strings"
	"sync"

	"github.com/golang-jwt/jwt/v4"
	"accesscontrolapi/config"
)

var jwksURLTemplate = "https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json"

type jwksCache struct {
	keys map[string]*rsa.PublicKey
	mu   sync.Mutex
}

var cache = &jwksCache{keys: make(map[string]*rsa.PublicKey)}

// ✅ Verify JWT Using AWS Cognito Public Keys
func VerifyJWTWithCognito(token string) (map[string]interface{}, error) {
	region := config.Config.AwsCognito.Region
	userPoolID := config.Config.AwsCognito.UserPoolId
	clientID := config.Config.AwsCognito.ClientId

	if region == "" || userPoolID == "" || clientID == "" {
		return nil, errors.New("missing AWS Cognito configuration")
	}

	jwksURL := fmt.Sprintf(jwksURLTemplate, region, userPoolID)

	// Parse the JWT
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Fetch the key ID from the token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing key ID in token header")
		}

		// Get the public key from the JWKS
		return getPublicKey(jwksURL, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWT: %v", err)
	}

	// Extract and validate claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, errors.New("invalid token claims")
	}

	// ✅ Determine whether it's an Access Token or an ID Token
	tokenUse, ok := claims["token_use"].(string)
	if !ok {
		return nil, errors.New("missing token_use claim")
	}

	if tokenUse == "access" {
		// ✅ If it's an Access Token, check `client_id`
		if claims["client_id"] != clientID {
			return nil, errors.New("invalid audience: client_id does not match")
		}
	} else if tokenUse == "id" {
		// ✅ If it's an ID Token, check `aud`
		if claims["aud"] != clientID {
			return nil, errors.New("invalid audience: aud does not match")
		}
	} else {
		return nil, errors.New("invalid token: neither access nor id token")
	}

	// ✅ Check issuer
	expectedIssuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolID)
	if claims["iss"] != expectedIssuer {
		return nil, errors.New("invalid issuer")
	}

	return claims, nil
}
// ✅ Fetch and Cache AWS Cognito Public Key
func getPublicKey(jwksURL, kid string) (*rsa.PublicKey, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	// Check if key is already in the cache
	if key, ok := cache.keys[kid]; ok {
		return key, nil
	}

	// Fetch the JWKS
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %v", err)
	}

	// Parse the JWKS
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %v", err)
	}

	// Find the key by its ID
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			n, err := jwt.DecodeSegment(key.N)
			if err != nil {
				return nil, fmt.Errorf("failed to decode key modulus: %v", err)
			}

			e, err := jwt.DecodeSegment(key.E)
			if err != nil {
				return nil, fmt.Errorf("failed to decode key exponent: %v", err)
			}

			pubKey := &rsa.PublicKey{
				N: new(big.Int).SetBytes(n),
				E: int(new(big.Int).SetBytes(e).Int64()),
			}

			// Cache the key for future use
			cache.keys[kid] = pubKey
			return pubKey, nil
		}
	}

	return nil, fmt.Errorf("key ID %s not found in JWKS", kid)
}
