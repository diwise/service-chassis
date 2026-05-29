package env

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/diwise/service-chassis/pkg/infrastructure/o11y/logging"
)

func GetVariableOrDefault[T string | int | bool](ctx context.Context, envVar string, defaultValue T) T {
	var val T
	value := os.Getenv(envVar)
	if value == "" {
		return defaultValue
	}

	switch any(val).(type) {
	case string:
		return any(value).(T)
	case int:
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return defaultValue
		}
		return any(parsed).(T)
	case bool:
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return defaultValue
		}
		return any(parsed).(T)
	default:
		panic(fmt.Sprintf("unsupported type: %T", val))
	}
}

func GetVariableOrDie(ctx context.Context, envVar, description string) string {
	value := os.Getenv(envVar)
	if value == "" {
		logger := logging.GetFromContext(ctx)
		msg := fmt.Sprintf("please set %s to a valid %s.", envVar, description)
		logger.Error(msg)
		panic(msg)
	}
	return value
}
