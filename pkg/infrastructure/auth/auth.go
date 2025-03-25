package auth

import "context"

type tenantsContextKey struct {
	name string
}

var allowedTenantsCtxKey = &tenantsContextKey{"allowed-tenants"}

func NewContextWithAllowedTenants(ctx context.Context, tenants []string) context.Context {
	ctx = context.WithValue(ctx, allowedTenantsCtxKey, tenants)
	return ctx
}

func GetFromContext(ctx context.Context) []string {
	tenants, ok := ctx.Value(allowedTenantsCtxKey).([]string)
	if !ok {
		return []string{}
	}
	return tenants
}
