package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type contextKeyOperatorID struct{}
type contextKeyRole struct{}

var jwtSecret = func() []byte {
	s := os.Getenv("DM_JWT_SECRET")
	if s == "" {
		panic("DM_JWT_SECRET environment variable is not set")
	}
	return []byte(s)
}()

type dmClaims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// IssueToken mints an access token (8h) and a refresh token (7d) for an operator.
func IssueToken(operatorID, role string) (access, refresh string, err error) {
	now := time.Now()
	sign := func(claims *dmClaims) (string, error) {
		return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
	}
	access, err = sign(&dmClaims{
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   operatorID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(8 * time.Hour)),
		},
	})
	if err != nil {
		return
	}
	refresh, err = sign(&dmClaims{
		Role: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   operatorID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(7 * 24 * time.Hour)),
		},
	})
	return
}

func validateToken(tokenStr string) (*dmClaims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &dmClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil || !tok.Valid {
		return nil, errors.New("invalid token")
	}
	return tok.Claims.(*dmClaims), nil
}

// ----- gRPC interceptors ---------------------------------------------------

var publicGRPCMethods = map[string]bool{
	"/dm.v1.AuthService/Login": true,
}

// AuthInterceptor validates JWT for every unary gRPC call that isn't public.
func AuthInterceptor(log *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if publicGRPCMethods[info.FullMethod] {
			return handler(ctx, req)
		}
		claims, err := tokenFromGRPCCtx(ctx)
		if err != nil {
			log.Warn("grpc auth rejected", zap.String("method", info.FullMethod), zap.Error(err))
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		ctx = context.WithValue(ctx, contextKeyOperatorID{}, claims.Subject)
		ctx = context.WithValue(ctx, contextKeyRole{}, claims.Role)
		return handler(ctx, req)
	}
}

// AuditInterceptor writes a structured log line for every unary gRPC call.
func AuditInterceptor(log *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		operatorID, _ := ctx.Value(contextKeyOperatorID{}).(string)
		start := time.Now()
		resp, err := handler(ctx, req)
		log.Info("grpc",
			zap.String("method", info.FullMethod),
			zap.String("operator", operatorID),
			zap.Duration("dur", time.Since(start)),
			zap.Error(err),
		)
		return resp, err
	}
}

// StreamAuthInterceptor validates JWT for gRPC server-streaming calls.
func StreamAuthInterceptor(log *zap.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		claims, err := tokenFromGRPCCtx(ss.Context())
		if err != nil {
			log.Warn("grpc stream auth rejected", zap.String("method", info.FullMethod), zap.Error(err))
			return status.Error(codes.Unauthenticated, "invalid token")
		}
		log.Debug("grpc stream opened", zap.String("method", info.FullMethod), zap.String("operator", claims.Subject))
		return handler(srv, ss)
	}
}

func tokenFromGRPCCtx(ctx context.Context) (*dmClaims, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("no metadata")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return nil, errors.New("missing authorization metadata")
	}
	return validateToken(strings.TrimPrefix(vals[0], "Bearer "))
}

// ----- HTTP middleware ------------------------------------------------------

// httpAuth validates a Bearer JWT and injects operator context values.
// Accepts the token via Authorization header OR ?token= query param.
// The query-param fallback exists because browsers cannot set custom headers
// on EventSource (SSE) connections.
func httpAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" {
			raw = r.URL.Query().Get("token")
		}
		claims, err := validateToken(raw)
		if err != nil || claims.Role == "refresh" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), contextKeyOperatorID{}, claims.Subject)
		ctx = context.WithValue(ctx, contextKeyRole{}, claims.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func operatorIDFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(contextKeyOperatorID{}).(string)
	return v
}
