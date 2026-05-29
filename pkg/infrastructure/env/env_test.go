package env_test

import (
	"context"
	"testing"

	"github.com/diwise/service-chassis/pkg/infrastructure/env"
	"github.com/matryer/is"
)

func TestGetVariableOrDefault(t *testing.T) {
	ctx := context.Background()

	t.Run("returns default for unset variables", func(t *testing.T) {
		is := is.New(t)

		is.Equal(env.GetVariableOrDefault(ctx, "SERVICE_CHASSIS_UNSET_STRING", "default"), "default")
		is.Equal(env.GetVariableOrDefault(ctx, "SERVICE_CHASSIS_UNSET_INT", 42), 42)
		is.Equal(env.GetVariableOrDefault(ctx, "SERVICE_CHASSIS_UNSET_BOOL", true), true)
	})

	t.Run("parses supported variable types", func(t *testing.T) {
		is := is.New(t)
		t.Setenv("SERVICE_CHASSIS_STRING", "configured")
		t.Setenv("SERVICE_CHASSIS_INT", "7")
		t.Setenv("SERVICE_CHASSIS_BOOL", "false")

		is.Equal(env.GetVariableOrDefault(ctx, "SERVICE_CHASSIS_STRING", "default"), "configured")
		is.Equal(env.GetVariableOrDefault(ctx, "SERVICE_CHASSIS_INT", 42), 7)
		is.Equal(env.GetVariableOrDefault(ctx, "SERVICE_CHASSIS_BOOL", true), false)
	})

	t.Run("returns default for invalid values", func(t *testing.T) {
		is := is.New(t)
		t.Setenv("SERVICE_CHASSIS_INVALID_INT", "seven")
		t.Setenv("SERVICE_CHASSIS_INVALID_BOOL", "definitely")

		is.Equal(env.GetVariableOrDefault(ctx, "SERVICE_CHASSIS_INVALID_INT", 42), 42)
		is.Equal(env.GetVariableOrDefault(ctx, "SERVICE_CHASSIS_INVALID_BOOL", true), true)
	})
}
