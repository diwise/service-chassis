package os

import (
	"os"

	"github.com/rs/zerolog"
)

func GetEnvironmentVariableOrDie(log zerolog.Logger, envVar, description string) string {
	value := os.Getenv(envVar)
	if value == "" {
		log.Fatal().Msgf("please set %s to a valid %s.", envVar, description)
	}
	return value
}
