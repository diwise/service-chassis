package env

import (
	"os"

	"github.com/rs/zerolog"
)

func GetVariableOrDefault(log zerolog.Logger, envVar, defaultValue string) string {
	value := os.Getenv(envVar)
	if value == "" {
		return defaultValue
	}
	return value
}

func GetVariableOrDie(log zerolog.Logger, envVar, description string) string {
	value := os.Getenv(envVar)
	if value == "" {
		log.Fatal().Msgf("please set %s to a valid %s.", envVar, description)
	}
	return value
}
