package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"opennofrp/pkg/protocol"
)

func (s *Session) RequestUpdate(ctx context.Context) (protocol.ClientUpdateResult, error) {
	if !s.HasCapability(protocol.CapSelfUpdate) {
		return protocol.ClientUpdateResult{}, errors.New("该客户端尚不支持远程更新，请先在机器上手动升级一次")
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return protocol.ClientUpdateResult{}, err
	}
	id := hex.EncodeToString(idBytes)
	s.mu.Lock()
	if s.updateResult != nil {
		s.mu.Unlock()
		return protocol.ClientUpdateResult{}, errors.New("这台机器已有更新任务，请稍后再试")
	}
	ch := make(chan protocol.ClientUpdateResult, 1)
	s.updateID = id
	s.lastUpdateID = id
	s.updateRestartError = ""
	s.updateResult = ch
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.updateID = ""; s.updateResult = nil; s.mu.Unlock() }()
	if err := s.writeControl(protocol.ClientUpdateRequest{Type: protocol.MsgClientUpdate, RequestID: id}); err != nil {
		return protocol.ClientUpdateResult{}, err
	}
	var closed <-chan struct{}
	if s.Yamux != nil {
		closed = s.Yamux.CloseChan()
	}
	select {
	case result := <-ch:
		return result, nil
	case <-closed:
		// A result may have arrived immediately before the client restarted.
		select {
		case result := <-ch:
			return result, nil
		default:
		}
		return protocol.ClientUpdateResult{}, errors.New("客户端连接已断开，更新结果未知，请查看客户端日志和重新连接后的版本")
	case <-ctx.Done():
		return protocol.ClientUpdateResult{}, ctx.Err()
	}
}

func (s *Session) ReceiveUpdateResult(result protocol.ClientUpdateResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if result.RequestID == s.lastUpdateID && result.Status == "failed" {
		s.updateRestartError = result.Error
	}
	if s.updateResult == nil || s.updateID != result.RequestID {
		return
	}
	select {
	case s.updateResult <- result:
	default:
	}
}

func (s *Session) UpdateRestartError(requestID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if requestID != s.lastUpdateID {
		return ""
	}
	return s.updateRestartError
}

func (s *Session) AcknowledgeUpdate(requestID string) error {
	return s.writeControl(protocol.ClientUpdateRequest{Type: protocol.MsgClientUpdateAck, RequestID: requestID})
}
