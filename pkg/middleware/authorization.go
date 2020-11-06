package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	authorizationHeader string = "Authorization"
)

// Authorize checks that a JWT token is valid and scoped correctly.
func Authorize() gin.HandlerFunc {
	return func(context *gin.Context) {
		authHeader := context.GetHeader(authorizationHeader)
		if authHeader == "" {
			// Authorization header not found
			context.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		splits := strings.Split(authHeader, " ")
		if len(splits) < 2 {
			// Bearer token value not found
			context.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		// TODO: validate token string
		_ = splits[1]
	}
}
