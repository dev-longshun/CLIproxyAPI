package configaccess

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v6/sdk/access"
)

func TestProviderAuthenticateWithManagedKey(t *testing.T) {
	t.Parallel()

	manager, err := NewManagedAPIKeyManager(filepath.Join(t.TempDir(), "managed.json"))
	if err != nil {
		t.Fatalf("NewManagedAPIKeyManager() error: %v", err)
	}

	days := 1.0
	created, err := manager.Create(ManagedAPIKeyCreateInput{
		Name:         "managed",
		DurationDays: &days,
	})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	p := newProvider("test-provider", []string{"static-key"}, manager)
	req := httptest.NewRequest(http.MethodGet, "https://example.com/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+created.Key)

	result, authErr := p.Authenticate(req.Context(), req)
	if authErr != nil {
		t.Fatalf("Authenticate() unexpected error: %v", authErr)
	}
	if result == nil {
		t.Fatal("expected non-nil auth result")
	}
	if result.Principal != created.Key {
		t.Fatalf("principal mismatch: got %q want %q", result.Principal, created.Key)
	}
	if result.Metadata["key_type"] != "managed" {
		t.Fatalf("expected key_type=managed, got %q", result.Metadata["key_type"])
	}
}

func TestProviderAuthenticateManagedKeyDisabledExpiredAndQuota(t *testing.T) {
	t.Parallel()

	manager, err := NewManagedAPIKeyManager(filepath.Join(t.TempDir(), "managed.json"))
	if err != nil {
		t.Fatalf("NewManagedAPIKeyManager() error: %v", err)
	}

	disabledKey, err := manager.Create(ManagedAPIKeyCreateInput{Name: "disabled"})
	if err != nil {
		t.Fatalf("Create(disabled) error: %v", err)
	}
	_, err = manager.Update(disabledKey.ID, ManagedAPIKeyUpdateInput{Enabled: OptionalBool{Set: true, Value: false}})
	if err != nil {
		t.Fatalf("Update(disabled) error: %v", err)
	}

	expiresAt := time.Now().UTC().Add(-time.Minute)
	expiredKey, err := manager.Create(ManagedAPIKeyCreateInput{Name: "expired", ExpiresAt: &expiresAt})
	if err != nil {
		t.Fatalf("Create(expired) error: %v", err)
	}

	quota := int64(1)
	quotaKey, err := manager.Create(ManagedAPIKeyCreateInput{Name: "quota", QuotaLimit: &quota})
	if err != nil {
		t.Fatalf("Create(quota) error: %v", err)
	}
	_ = manager.Authenticate(quotaKey.Key, time.Now().UTC())

	p := newProvider("test-provider", nil, manager)

	run := func(key string) *sdkaccess.AuthError {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		_, authErr := p.Authenticate(req.Context(), req)
		return authErr
	}

	disabledErr := run(disabledKey.Key)
	if !sdkaccess.IsAuthErrorCode(disabledErr, sdkaccess.AuthErrorCodeDisabledCredential) {
		t.Fatalf("expected disabled_credential, got %#v", disabledErr)
	}

	expiredErr := run(expiredKey.Key)
	if !sdkaccess.IsAuthErrorCode(expiredErr, sdkaccess.AuthErrorCodeExpiredCredential) {
		t.Fatalf("expected expired_credential, got %#v", expiredErr)
	}

	quotaErr := run(quotaKey.Key)
	if !sdkaccess.IsAuthErrorCode(quotaErr, sdkaccess.AuthErrorCodeQuotaExceeded) {
		t.Fatalf("expected quota_exceeded, got %#v", quotaErr)
	}
}
