package api

import (
	"github.com/BroJustLeaveMeAlone/C2-Adversary/server/internal/collab"
	"github.com/BroJustLeaveMeAlone/C2-Adversary/server/internal/session"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// RegisterAll wires all gRPC service implementations into srv.
// Phase 1 stub: the operator API is served via the REST gateway.
// Full gRPC service registration will be added in Phase 2 after protoc codegen.
func RegisterAll(srv *grpc.Server, sessions *session.Manager, bus *collab.Bus, log *zap.Logger) {
	log.Info("gRPC services: Phase 2 protoc codegen pending — operators use REST gateway")
	// suppress unused-parameter warnings until Phase 2 wires actual handlers
	_ = srv
	_ = sessions
	_ = bus
}
