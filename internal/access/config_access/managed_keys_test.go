package configaccess

import (
	"path/filepath"
	"testing"
	"time"
)

func TestManagedAPIKeyPendingActivationFlow(t *testing.T) {
	t.Parallel()

	manager, err := NewManagedAPIKeyManager(filepath.Join(t.TempDir(), "managed.json"))
	if err != nil {
		t.Fatalf("NewManagedAPIKeyManager() error: %v", err)
	}

	days := 1.0
	created, err := manager.Create(ManagedAPIKeyCreateInput{
		Name:         "pending-key",
		DurationDays: &days,
	})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if status := created.Status(time.Now().UTC()); status != ManagedAPIKeyStatusPending {
		t.Fatalf("expected pending status, got %q", status)
	}

	now := time.Now().UTC()
	outcome := manager.Authenticate(created.Key, now)
	if !outcome.Matched {
		t.Fatal("expected managed key to match")
	}
	if outcome.Status != ManagedAPIKeyStatusActive {
		t.Fatalf("expected active status after first use, got %q", outcome.Status)
	}

	stored, ok := manager.Get(created.ID)
	if !ok {
		t.Fatalf("Get(%d): key not found", created.ID)
	}
	if stored.ActivatedAt == nil {
		t.Fatal("expected activatedAt to be set")
	}
	if stored.ExpiresAt == nil {
		t.Fatal("expected expiresAt to be set")
	}
	if stored.QuotaUsed != 1 {
		t.Fatalf("expected quotaUsed=1, got %d", stored.QuotaUsed)
	}
}

func TestManagedAPIKeyQuotaAndDisable(t *testing.T) {
	t.Parallel()

	manager, err := NewManagedAPIKeyManager(filepath.Join(t.TempDir(), "managed.json"))
	if err != nil {
		t.Fatalf("NewManagedAPIKeyManager() error: %v", err)
	}

	limit := int64(1)
	created, err := manager.Create(ManagedAPIKeyCreateInput{
		Name:       "quota-key",
		QuotaLimit: &limit,
	})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	first := manager.Authenticate(created.Key, time.Now().UTC())
	if !first.Matched || first.Status != ManagedAPIKeyStatusActive {
		t.Fatalf("expected first request to be active, got matched=%v status=%q", first.Matched, first.Status)
	}
	second := manager.Authenticate(created.Key, time.Now().UTC().Add(time.Second))
	if !second.Matched || second.Status != ManagedAPIKeyStatusQuotaReached {
		t.Fatalf("expected quota reached, got matched=%v status=%q", second.Matched, second.Status)
	}

	_, err = manager.Update(created.ID, ManagedAPIKeyUpdateInput{
		Enabled: OptionalBool{Set: true, Value: false},
	})
	if err != nil {
		t.Fatalf("Update(disable) error: %v", err)
	}
	disabled := manager.Authenticate(created.Key, time.Now().UTC().Add(2*time.Second))
	if !disabled.Matched || disabled.Status != ManagedAPIKeyStatusDisabled {
		t.Fatalf("expected disabled status, got matched=%v status=%q", disabled.Matched, disabled.Status)
	}
}

func TestManagedAPIKeyRenewExtendsActiveDuration(t *testing.T) {
	t.Parallel()

	manager, err := NewManagedAPIKeyManager(filepath.Join(t.TempDir(), "managed.json"))
	if err != nil {
		t.Fatalf("NewManagedAPIKeyManager() error: %v", err)
	}

	days := 1.0
	created, err := manager.Create(ManagedAPIKeyCreateInput{
		Name:         "renew-key",
		DurationDays: &days,
	})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	manager.Authenticate(created.Key, time.Now().UTC())
	active, ok := manager.Get(created.ID)
	if !ok || active.ExpiresAt == nil {
		t.Fatalf("expected active key with expiresAt, got ok=%v expiresAt=%v", ok, active.ExpiresAt)
	}
	oldExpires := *active.ExpiresAt

	extendBy := 2.0
	renewed, err := manager.Renew(created.ID, ManagedAPIKeyRenewInput{
		DurationDays: &extendBy,
	})
	if err != nil {
		t.Fatalf("Renew() error: %v", err)
	}
	if renewed.ExpiresAt == nil {
		t.Fatal("expected renewed expiresAt")
	}
	if !renewed.ExpiresAt.After(oldExpires) {
		t.Fatalf("expected renewed expiresAt %s to be after old %s", renewed.ExpiresAt, oldExpires)
	}
	if renewed.DurationDays == nil || *renewed.DurationDays <= days {
		t.Fatalf("expected durationDays to increase, got %v", renewed.DurationDays)
	}
}
