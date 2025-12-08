package grpc_handler

import (
	"context"
	"strings"

	"github.com/GroVlAn/auth-example/internal/core"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	excludedAccessTokenMethods = []string{
		"/Login",
		"/VerifyAccessToken",
		"/UpdateAccessToken",
		"/Logout",
		"/LogoutAllDevices",
	}
	includeRefreshTokenMethods = []string{
		"/Logout",
		"/LogoutAllDevices",
	}
)

func (h *GRPCHandler) VerifyAccessTokenInterceptor(
	srv any,
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if !info.IsClientStream &&
		includeMethod(info.FullMethod, excludedAccessTokenMethods) {
		return handler(srv, ss)
	}

	md, ok := metadata.FromIncomingContext(ss.Context())
	accToken := md["access-token"]

	if !ok || len(accToken) == 0 {
		return status.Errorf(codes.Unauthenticated, "method %s requires authentication", info.FullMethod)
	}

	tokenDetails, err := h.AuthService.VerifyAccessToken(ss.Context(), accToken[0])
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "method %s requires authentication", info.FullMethod)
	}

	ctx := context.WithValue(ss.Context(), core.AccessTokenKey, tokenDetails)

	wrapped := grpc_middleware.WrapServerStream(ss)
	wrapped.WrappedContext = ctx

	return handler(srv, wrapped)
}

func (h *GRPCHandler) VerifyRefreshTokenInterceptor(
	srv any,
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if !info.IsClientStream &&
		!includeMethod(info.FullMethod, includeRefreshTokenMethods) {
		return handler(srv, ss)
	}

	md, ok := metadata.FromIncomingContext(ss.Context())
	refToken := md["refresh-token"]

	if !ok || len(refToken) == 0 {
		return status.Errorf(codes.Unauthenticated, "method %s requires authentication", info.FullMethod)
	}

	tokenDetails, err := h.AuthService.VerifyRefreshToken(ss.Context(), refToken[0])
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "method %s requires authentication", info.FullMethod)
	}

	ctx := context.WithValue(ss.Context(), core.AccessTokenKey, tokenDetails)

	wrapped := grpc_middleware.WrapServerStream(ss)
	wrapped.WrappedContext = ctx

	return handler(srv, wrapped)
}

func includeMethod(fullMethod string, excludedMethods []string) bool {
	for _, m := range excludedMethods {
		if strings.HasSuffix(fullMethod, m) {
			return true
		}
	}
	return false
}
