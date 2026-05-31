package store

import (
	"os"
	"testing"
	"time"
)

func TestNewCreatesStateWithTempFile(t *testing.T) {
	t.Parallel()

	state, tmpFile := newTestState(t)
	defer os.Remove(tmpFile)

	if state == nil {
		t.Fatalf("New returned nil state")
	}
	if _, err := os.Stat(tmpFile); err != nil {
		t.Fatalf("os.Stat(%q) returned error: %v", tmpFile, err)
	}
}

func TestAccessKeys(t *testing.T) {
	t.Parallel()

	t.Run("add key then validate", func(t *testing.T) {
		t.Parallel()

		state, tmpFile := newTestState(t)
		defer os.Remove(tmpFile)

		if err := state.AddKey("test-token", "test key", ""); err != nil {
			t.Fatalf("AddKey returned error: %v", err)
		}
		if !state.ValidateKey("test-token") {
			t.Fatalf("ValidateKey returned false for added key")
		}
	})

	t.Run("delete key removes token", func(t *testing.T) {
		t.Parallel()

		state, tmpFile := newTestState(t)
		defer os.Remove(tmpFile)

		if err := state.AddKey("delete-token", "delete key", ""); err != nil {
			t.Fatalf("AddKey returned error: %v", err)
		}

		key, ok := state.GetKeyByToken("delete-token")
		if !ok {
			t.Fatalf("GetKeyByToken returned false for added key")
		}
		if err := state.DeleteKey(key.ID); err != nil {
			t.Fatalf("DeleteKey returned error: %v", err)
		}
		if state.ValidateKey("delete-token") {
			t.Fatalf("ValidateKey returned true after DeleteKey")
		}
	})
}

func TestAdminSessions(t *testing.T) {
	t.Parallel()

	t.Run("create and validate session", func(t *testing.T) {
		t.Parallel()

		state, tmpFile := newTestState(t)
		defer os.Remove(tmpFile)

		user := authenticateTestAdmin(t, state, "admin-password")
		token, err := state.CreateAdminSession(user.ID)
		if err != nil {
			t.Fatalf("CreateAdminSession returned error: %v", err)
		}

		session, ok := state.ValidateAdminSession(token)
		if !ok {
			t.Fatalf("ValidateAdminSession returned false")
		}
		if session.UserID != user.ID {
			t.Errorf("session.UserID = %q, want %q", session.UserID, user.ID)
		}
		if session.Username != user.Username {
			t.Errorf("session.Username = %q, want %q", session.Username, user.Username)
		}
	})

	t.Run("cleanup expired session", func(t *testing.T) {
		t.Parallel()

		state, tmpFile := newTestState(t)
		defer os.Remove(tmpFile)

		user := authenticateTestAdmin(t, state, "admin-password")
		token := "expired-token"
		state.adminSessions[token] = AdminSession{
			UserID:    user.ID,
			Username:  user.Username,
			Role:      user.Role,
			ExpiresAt: time.Now().Add(-time.Hour),
		}

		state.CleanupExpiredSessions()
		if _, ok := state.ValidateAdminSession(token); ok {
			t.Fatalf("ValidateAdminSession returned true for expired session")
		}
	})
}

func TestAuthenticateAdminUser(t *testing.T) {
	t.Parallel()

	t.Run("correct password succeeds", func(t *testing.T) {
		t.Parallel()

		state, tmpFile := newTestState(t)
		defer os.Remove(tmpFile)

		user, err := state.AuthenticateAdminUser("admin", "admin-password")
		if err != nil {
			t.Fatalf("AuthenticateAdminUser returned error: %v", err)
		}
		if user.Username != "admin" {
			t.Errorf("user.Username = %q, want %q", user.Username, "admin")
		}
	})

	t.Run("wrong password fails", func(t *testing.T) {
		t.Parallel()

		state, tmpFile := newTestState(t)
		defer os.Remove(tmpFile)

		if _, err := state.AuthenticateAdminUser("admin", "wrong-password"); err == nil {
			t.Fatalf("AuthenticateAdminUser returned nil error")
		}
	})
}

func TestLogCountByUpstreamScope(t *testing.T) {
	t.Parallel()

	state, tmpFile := newTestState(t)
	defer os.Remove(tmpFile)

	logs := []ClientUpdateLog{
		{Time: time.Now(), UpstreamID: "upstream-a", Status: "ok"},
		{Time: time.Now(), UpstreamID: "upstream-b", Status: "ok"},
		{Time: time.Now(), UpstreamID: "upstream-a", Status: "error"},
	}
	for _, entry := range logs {
		if err := state.AppendClientLog(entry); err != nil {
			t.Fatalf("AppendClientLog returned error: %v", err)
		}
	}

	allowed := map[string]struct{}{"upstream-a": {}}
	if count := state.LogCountByUpstreamScope(allowed); count != 2 {
		t.Fatalf("LogCountByUpstreamScope returned %d, want 2", count)
	}
}

func newTestState(t *testing.T) (*State, string) {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "jsyproxy-state-*.json")
	if err != nil {
		t.Fatalf("os.CreateTemp returned error: %v", err)
	}
	path := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(path)
		t.Fatalf("tmpFile.Close returned error: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("os.Remove(%q) returned error: %v", path, err)
	}

	state, err := New(path, []string{"bootstrap-token"}, "10m", "admin", "admin-password")
	if err != nil {
		_ = os.Remove(path)
		t.Fatalf("New returned error: %v", err)
	}
	return state, path
}

func authenticateTestAdmin(t *testing.T, state *State, password string) AdminUser {
	t.Helper()

	user, err := state.AuthenticateAdminUser("admin", password)
	if err != nil {
		t.Fatalf("AuthenticateAdminUser returned error: %v", err)
	}
	return user
}
