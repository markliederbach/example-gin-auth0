package config

import (
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

const (
	logLevelVariable string = "LOG_LEVEL"

	defaultLogLevel log.Level = log.InfoLevel
)

// Config holds all configuration data about the currently-running service
type Config struct {
	// Required variables

	// Optional variables
	LogLevel log.Level
}

// Load creates a new instance of Config, using all available
// defaults and overrides.
func Load() Config {
	config := Config{
		LogLevel: fromEnvLogLevel(logLevelVariable, false, defaultLogLevel),
	}

	config.configureLogger()

	return config
}

func (c *Config) configureLogger() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	gin.SetMode(gin.ReleaseMode)

	switch c.LogLevel {
	case log.TraceLevel:
		gin.SetMode(gin.DebugMode)
		log.SetReportCaller(true)
	}

	log.SetLevel(c.LogLevel)
}

func fromEnvString(variable string, required bool, defaultValue string) string {
	rawValue, exists := fromEnv(variable, required)
	if !exists {
		rawValue = defaultValue
	}
	return rawValue
}

func fromEnvDuration(variable string, required bool, defaultValue time.Duration) time.Duration {
	var err error
	value := defaultValue
	rawValue, exists := fromEnv(variable, required)
	if exists {
		value, err = time.ParseDuration(rawValue)
		if err != nil {
			panic(err)
		}
	}
	return value
}

func fromEnvLogLevel(variable string, required bool, defaultValue log.Level) log.Level {
	var err error
	value := defaultValue
	rawValue, exists := fromEnv(variable, required)
	if exists {
		value, err = log.ParseLevel(rawValue)
		if err != nil {
			panic(err)
		}
	}
	return value
}

func fromEnv(variable string, required bool) (string, bool) {
	value, exists := os.LookupEnv(variable)
	if !exists && required {
		panic(fmt.Errorf("Missing required environment variable %s", variable))
	}
	return value, exists
}
