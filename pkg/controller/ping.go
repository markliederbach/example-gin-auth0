package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type PingController struct {
	log         *log.Entry
	group       *gin.RouterGroup
	pingMessage string
}

func NewPingController(group *gin.RouterGroup, pingMessage string) *PingController {
	pingController := &PingController{
		log:         log.WithFields(log.Fields{"logger": "PingController"}),
		group:       group,
		pingMessage: pingMessage,
	}

	// Register controller routes
	pingController.group.GET("/ping", pingController.Ping)

	return pingController
}

func (c *PingController) Ping(context *gin.Context) {
	c.log.Info("Handling ping request")
	context.JSON(http.StatusOK, gin.H{"message": c.pingMessage})
}
