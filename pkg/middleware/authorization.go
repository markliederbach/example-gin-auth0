package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

const (
	// Auth0 API
	audience string = "https://quickstarts/api"
	baseURL  string = "https://qtower.us.auth0.com"
	issuer   string = baseURL

	authorizationHeader string = "Authorization"
)

type AuthClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

type JWKSResponse struct {
	Keys []JSONWebKey `json:"keys"`
}

type JSONWebKey struct {
	Alg string   `json:"alg"`
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// Authorize checks that a JWT token is valid and scoped correctly.
func Authorize() gin.HandlerFunc {

	return func(context *gin.Context) {
		authHeader := context.GetHeader(authorizationHeader)
		if authHeader == "" {
			// Authorization header not found
			unauthorized(context)
			return
		}

		authHeaderParts := strings.Fields(authorizationHeader)
		if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
			// Bearer token value not found
			unauthorized(context)
			return
		}

		encodedToken := authHeaderParts[1]
		if encodedToken == "" {
			// Token is empty
			unauthorized(context)
			return
		}

		_, _, err := validateToken(encodedToken)
		if err != nil {
			// TODO: log the error
			forbidden(context)
			return
		}

		// TODO: Check scopes

		// TODO: Attach validate token data to context
	}
}

func validateToken(encodedToken string) (*jwt.Token, *AuthClaims, error) {
	now := jwt.TimeFunc().Unix()
	authClaims := &AuthClaims{}
	tokenParser := jwt.Parser{
		ValidMethods: []string{jwt.SigningMethodRS256.Alg()},
		// The default validation is not good enough
		// We'll do it ourselves below
		SkipClaimsValidation: true,
	}
	token, err := tokenParser.ParseWithClaims(encodedToken, authClaims, func(token *jwt.Token) (interface{}, error) {
		if valid := authClaims.VerifyAudience(audience, true); !valid {
			return nil, fmt.Errorf("Invalid audience")
		}

		if valid := authClaims.VerifyIssuer(issuer, true); !valid {
			return nil, fmt.Errorf("Invalid issuer")
		}

		cert, err := getPemCert(token)
		if err != nil {
			return nil, fmt.Errorf("Failed to retrieve PEM cert")
		}

		return jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
	})

	if err != nil {
		return nil, nil, err
	}

	// Additional claims validation
	validationError := new(jwt.ValidationError)

	if valid := authClaims.VerifyExpiresAt(now, true); !valid {
		delta := time.Unix(now, 0).Sub(time.Unix(authClaims.ExpiresAt, 0))
		validationError.Inner = fmt.Errorf("Token is expired by %v", delta)
		validationError.Errors |= jwt.ValidationErrorExpired
	}

	if valid := authClaims.VerifyIssuedAt(now, true); !valid {
		validationError.Inner = fmt.Errorf("Token used before issued")
		validationError.Errors |= jwt.ValidationErrorIssuedAt
	}

	if valid := authClaims.VerifyNotBefore(now, false); !valid {
		validationError.Inner = fmt.Errorf("Token is not valid yet")
		validationError.Errors |= jwt.ValidationErrorNotValidYet
	}

	if validationError.Errors != 0 {
		token.Valid = false
		return token, authClaims, validationError
	}

	return token, authClaims, nil
}

func unauthorized(context *gin.Context) {
	context.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
}

func forbidden(context *gin.Context) {
	context.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
}

func getPemCert(token *jwt.Token) (string, error) {
	// TODO: Caching response to avoid requests on every validate
	cert := ""
	certURL := fmt.Sprintf("%s/.well-known/jwks.json", baseURL)
	client := http.Client{Timeout: time.Second * 3}

	response, err := client.Get(certURL)
	if err != nil {
		return cert, err
	}

	if response.StatusCode != http.StatusOK {
		return cert, fmt.Errorf("%s: %s", certURL, response.Status)
	}

	defer response.Body.Close()

	jwksResponse := JWKSResponse{}
	if err := json.NewDecoder(response.Body).Decode(&jwksResponse); err != nil {
		return cert, err
	}

	for key := range jwksResponse.Keys {
		if token.Header["kid"] == jwksResponse.Keys[key].Kid {
			cert = fmt.Sprintf(
				"-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----",
				jwksResponse.Keys[key].X5c[0],
			)
		}
	}

	if cert == "" {
		return cert, fmt.Errorf("Unable to find appropriate key")
	}

	return cert, nil
}
