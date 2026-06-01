package env

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/diwise/service-chassis/pkg/infrastructure/o11y/logging"
)

var GetVariableOrDefault = GetVariableOrDefaultAs[string]

var GetVariableOrDie = GetVariableOrDieAs[string]

func GetVariableOrDefaultAs[T string | int | int32 | int64 | bool | time.Duration](ctx context.Context, envVar string, defaultValue T) T {
	value := os.Getenv(envVar)
	if value == "" {
		return defaultValue
	}

	parsed, err := parse[T](value)
	if err != nil {
		return defaultValue
	}

	return parsed
}

func GetVariableOrDieAs[T string | int | int32 | int64 | bool | time.Duration](ctx context.Context, envVar, description string) T {
	value := os.Getenv(envVar)

	if value == "" {
		logger := logging.GetFromContext(ctx)
		msg := fmt.Sprintf("please set %s to a valid %s.", envVar, description)
		logger.Error(msg)
		panic(msg)
	}

	parsed, err := parse[T](value)
	if err != nil {
		panic(err)
	}

	return parsed
}

func parse[T string | int | int32 | int64 | bool | time.Duration](value string) (T, error) {
	var val T

	switch any(val).(type) {
	case string:
		return any(value).(T), nil
	case int:
		parsed, err := strconv.Atoi(value)
		return any(parsed).(T), err
	case int32:
		parsed, err := strconv.ParseInt(value, 10, 32)
		return any(int32(parsed)).(T), err
	case int64:
		parsed, err := strconv.ParseInt(value, 10, 64)
		return any(parsed).(T), err
	case bool:
		parsed, err := strconv.ParseBool(value)
		return any(parsed).(T), err
	case time.Duration:
		parsed, err := time.ParseDuration(value)
		return any(parsed).(T), err
	default:
		panic(fmt.Sprintf("unsupported type: %T", val))
	}
}
