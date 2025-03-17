package auth

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	// "strings"
	"sync"

	"accesscontrolapi/config"

	"github.com/golang-jwt/jwt/v4"
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

	fmt.Println("✅ Starting JWT Verification...")

	// Parse the JWT
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		fmt.Println("🔍 Parsing JWT...")

		// Debug print: Show JWT Header
		// fmt.Printf("JWT Header: %+v\n", token.Header)

		// Ensure the signing method is RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			fmt.Printf("❌ Unexpected signing method: %v\n", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Debug print: Show JWT key ID (kid)
		kid, ok := token.Header["kid"].(string)
		if !ok {
			fmt.Println("❌ Missing 'kid' in token header")
			return nil, errors.New("missing key ID in token header")
		}
		fmt.Println("✅ Extracted Key ID (kid):", kid)

		// Get the public key from the JWKS
		publicKey, err := getPublicKey(jwksURL, kid)
		if err != nil {
			fmt.Printf("❌ Failed to fetch JWKS key for kid=%s: %v\n", kid, err)
			return nil, err
		}

		fmt.Println("✅ Successfully fetched public key")
		return publicKey, nil
	})
	if err != nil {
		fmt.Printf("❌ Failed to verify JWT: %v\n", err)
		return nil, fmt.Errorf("failed to verify JWT: %v", err)
	}

	fmt.Println("✅ JWT Parsed Successfully!")

	// Extract and validate claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		fmt.Println("❌ Invalid token claims")
		return nil, errors.New("invalid token claims")
	}

	// Debug: Print all claims
	fmt.Printf("🔍 JWT Claims: %+v\n", claims)

	// Extract `iat` (issued at) time
	iat, ok := claims["iat"].(float64)
	if !ok {
		fmt.Println("❌ Missing iat claim")
		return nil, errors.New("missing iat claim")
	}

	// ✅ Print Debugging Information
	currentTime := time.Now().Unix()
	fmt.Println("Current Server Time:", currentTime)
	fmt.Println("Token Issued At (iat):", int64(iat))
	fmt.Println("Time Difference (current - iat):", currentTime-int64(iat), "seconds")

	// ✅ Allow a 5-minute clock skew (300 seconds)
	if currentTime < int64(iat)-300 {
		fmt.Println("⚠️ Token used before issued! Possible clock skew issue.")
		return nil, errors.New("token used before issued (possible clock skew)")
	}

	fmt.Println("✅ Token timing looks good.")

	// ✅ Determine whether it's an Access Token or an ID Token
	tokenUse, ok := claims["token_use"].(string)
	if !ok {
		fmt.Println("❌ Missing token_use claim")
		return nil, errors.New("missing token_use claim")
	}

	if tokenUse == "access" {
		// ✅ If it's an Access Token, check `client_id`
		if claims["client_id"] != clientID {
			fmt.Println("❌ Invalid audience: client_id does not match")
			return nil, errors.New("invalid audience: client_id does not match")
		}
	} else if tokenUse == "id" {
		// ✅ If it's an ID Token, check `aud`
		if claims["aud"] != clientID {
			fmt.Println("❌ Invalid audience: aud does not match")
			return nil, errors.New("invalid audience: aud does not match")
		}
	} else {
		fmt.Println("❌ Invalid token type (neither access nor id token)")
		return nil, errors.New("invalid token: neither access nor id token")
	}

	// ✅ Check issuer
	expectedIssuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolID)
	if claims["iss"] != expectedIssuer {
		fmt.Println("❌ Invalid issuer")
		return nil, errors.New("invalid issuer")
	}

	fmt.Println("✅ Token Verified Successfully!")
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
