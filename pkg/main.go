package main

import (
	"github.com/gin-gonic/gin"
	"github.com/markliederbach/example-gin-auth0/pkg/config"
	"github.com/markliederbach/example-gin-auth0/pkg/controller"
	"github.com/markliederbach/example-gin-auth0/pkg/middleware"
)

func main() {
	// TODO: Use config for stuff
	_ = config.Load()

	// Core router
	router := gin.New()
	router.Use(middleware.GinLogger(), gin.Recovery())

	// Public endpoints
	public := router.Group("/public")
	controller.NewPingController(public, "public pong")

	// Private endpoints
	private := router.Group("/private")
	private.Use(middleware.Authorize())
	controller.NewPingController(private, "secure pong")

	// Serve API on default port (8080)
	router.Run()
}
