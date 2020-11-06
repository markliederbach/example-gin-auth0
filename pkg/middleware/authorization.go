package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

const (
	// API identifier
	audience string = "https://quickstarts/api"

	// Auth0 Tenant
	issuer string = "https://qtower.us.auth0.com/"

	authorizationHeader string = "Authorization"
)

type AuthClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
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

func getPemCert(token *jwt.Token) (string, error) {
	// TODO
	return "", nil
}
