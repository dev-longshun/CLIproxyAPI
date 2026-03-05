package configaccess

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	managedAPIKeyStoreFileName = "managed-api-keys.json"

	ManagedAPIKeyStatusActive       = "active"
	ManagedAPIKeyStatusPending      = "pending"
	ManagedAPIKeyStatusDisabled     = "disabled"
	ManagedAPIKeyStatusExpired      = "expired"
	ManagedAPIKeyStatusQuotaReached = "quota_reached"
)

var (
	ErrManagedAPIKeyNotFound  = errors.New("managed API key not found")
	ErrManagedAPIKeyDuplicate = errors.New("managed API key already exists")
)

type OptionalString struct {
	Set   bool
	Value string
}

type OptionalBool struct {
	Set   bool
	Value bool
}

type OptionalTime struct {
	Set   bool
	Value *time.Time
}

type OptionalFloat64 struct {
	Set   bool
	Value *float64
}

type OptionalInt64 struct {
	Set   bool
	Value *int64
}

type ManagedAPIKey struct {
	ID           int64      `json:"id"`
	Key          string     `json:"key"`
	Name         string     `json:"name"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
	ActivatedAt  *time.Time `json:"activatedAt,omitempty"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
	DurationDays *float64   `json:"durationDays,omitempty"`
	QuotaLimit   *int64     `json:"quotaLimit,omitempty"`
	QuotaUsed    int64      `json:"quotaUsed"`
	LastUsedAt   *time.Time `json:"lastUsedAt,omitempty"`
}

func (k ManagedAPIKey) status(now time.Time) string {
	if !k.Enabled {
		return ManagedAPIKeyStatusDisabled
	}
	if k.QuotaLimit != nil && k.QuotaUsed >= *k.QuotaLimit {
		return ManagedAPIKeyStatusQuotaReached
	}
	if k.DurationDays != nil && k.ActivatedAt == nil {
		return ManagedAPIKeyStatusPending
	}
	if k.ExpiresAt != nil && !now.Before(*k.ExpiresAt) {
		return ManagedAPIKeyStatusExpired
	}
	return ManagedAPIKeyStatusActive
}

func (k ManagedAPIKey) Status(now time.Time) string {
	return k.status(now)
}

type ManagedAPIKeyCreateInput struct {
	Name         string
	Enabled      *bool
	ExpiresAt    *time.Time
	DurationDays *float64
	QuotaLimit   *int64
	RawKey       string
}

type ManagedAPIKeyUpdateInput struct {
	Name           OptionalString
	Enabled        OptionalBool
	ExpiresAt      OptionalTime
	DurationDays   OptionalFloat64
	QuotaLimit     OptionalInt64
	ResetQuotaUsed bool
}

type ManagedAPIKeyRenewInput struct {
	DurationDays   *float64
	QuotaLimit     OptionalInt64
	QuotaIncrease  *int64
	ResetQuotaUsed bool
}

type ManagedAPIKeyAuthOutcome struct {
	Matched bool
	Key     ManagedAPIKey
	Status  string
}

type managedAPIKeyStore struct {
	Version int             `json:"version"`
	NextID  int64           `json:"nextId"`
	Items   []ManagedAPIKey `json:"items"`
}

type ManagedAPIKeyManager struct {
	mu       sync.RWMutex
	filePath string
	nextID   int64
	byID     map[int64]*ManagedAPIKey
	byKey    map[string]*ManagedAPIKey
}

func NewManagedAPIKeyManager(filePath string) (*ManagedAPIKeyManager, error) {
	cleanPath := strings.TrimSpace(filePath)
	if cleanPath == "" {
		return nil, fmt.Errorf("managed API key file path is empty")
	}
	if stat, err := os.Stat(cleanPath); err == nil && stat.IsDir() {
		return nil, fmt.Errorf("managed API key path %q is a directory", cleanPath)
	}

	m := &ManagedAPIKeyManager{
		filePath: cleanPath,
		nextID:   1,
		byID:     make(map[int64]*ManagedAPIKey),
		byKey:    make(map[string]*ManagedAPIKey),
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func ManagedAPIKeyFilePath(authDir string) string {
	trimmed := strings.TrimSpace(authDir)
	if trimmed == "" {
		trimmed = ".cli-proxy-api"
	}
	return filepath.Join(trimmed, managedAPIKeyStoreFileName)
}

func (m *ManagedAPIKeyManager) FilePath() string {
	if m == nil {
		return ""
	}
	return m.filePath
}

func (m *ManagedAPIKeyManager) HasKeys() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	has := len(m.byID) > 0
	m.mu.RUnlock()
	return has
}

func (m *ManagedAPIKeyManager) List() []ManagedAPIKey {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	items := make([]ManagedAPIKey, 0, len(m.byID))
	for _, key := range m.byID {
		items = append(items, cloneManagedAPIKey(*key))
	}
	m.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	return items
}

func (m *ManagedAPIKeyManager) Get(id int64) (ManagedAPIKey, bool) {
	if m == nil {
		return ManagedAPIKey{}, false
	}
	m.mu.RLock()
	key, ok := m.byID[id]
	if !ok || key == nil {
		m.mu.RUnlock()
		return ManagedAPIKey{}, false
	}
	out := cloneManagedAPIKey(*key)
	m.mu.RUnlock()
	return out, true
}

func (m *ManagedAPIKeyManager) Create(input ManagedAPIKeyCreateInput) (ManagedAPIKey, error) {
	if m == nil {
		return ManagedAPIKey{}, fmt.Errorf("managed API key manager is nil")
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return ManagedAPIKey{}, fmt.Errorf("name is required")
	}
	if input.DurationDays != nil && input.ExpiresAt != nil {
		return ManagedAPIKey{}, fmt.Errorf("durationDays and expiresAt cannot be set at the same time")
	}
	if input.DurationDays != nil && *input.DurationDays <= 0 {
		return ManagedAPIKey{}, fmt.Errorf("durationDays must be greater than 0")
	}
	if input.QuotaLimit != nil && *input.QuotaLimit < 0 {
		return ManagedAPIKey{}, fmt.Errorf("quotaLimit cannot be negative")
	}

	apiKey := strings.TrimSpace(input.RawKey)
	if apiKey == "" {
		generated, err := generateManagedAPIKey()
		if err != nil {
			return ManagedAPIKey{}, fmt.Errorf("generate key: %w", err)
		}
		apiKey = generated
	}

	now := time.Now().UTC()
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.byKey[apiKey]; exists {
		return ManagedAPIKey{}, ErrManagedAPIKeyDuplicate
	}

	id := m.nextID
	m.nextID++
	entry := &ManagedAPIKey{
		ID:           id,
		Key:          apiKey,
		Name:         name,
		Enabled:      enabled,
		CreatedAt:    now,
		UpdatedAt:    now,
		DurationDays: cloneFloat64Ptr(input.DurationDays),
		ExpiresAt:    normalizeTimePtr(input.ExpiresAt),
		QuotaLimit:   cloneInt64Ptr(input.QuotaLimit),
		QuotaUsed:    0,
	}
	m.byID[id] = entry
	m.byKey[apiKey] = entry

	if err := m.saveLocked(); err != nil {
		delete(m.byID, id)
		delete(m.byKey, apiKey)
		if m.nextID > 1 {
			m.nextID--
		}
		return ManagedAPIKey{}, err
	}

	return cloneManagedAPIKey(*entry), nil
}

func (m *ManagedAPIKeyManager) Update(id int64, input ManagedAPIKeyUpdateInput) (ManagedAPIKey, error) {
	if m == nil {
		return ManagedAPIKey{}, fmt.Errorf("managed API key manager is nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.byID[id]
	if !ok || entry == nil {
		return ManagedAPIKey{}, ErrManagedAPIKeyNotFound
	}

	if input.Name.Set {
		name := strings.TrimSpace(input.Name.Value)
		if name == "" {
			return ManagedAPIKey{}, fmt.Errorf("name cannot be empty")
		}
		entry.Name = name
	}
	if input.Enabled.Set {
		entry.Enabled = input.Enabled.Value
	}

	now := time.Now().UTC()

	if input.DurationDays.Set {
		if input.DurationDays.Value == nil {
			entry.DurationDays = nil
			entry.ActivatedAt = nil
		} else {
			days := *input.DurationDays.Value
			if days <= 0 {
				return ManagedAPIKey{}, fmt.Errorf("durationDays must be greater than 0")
			}
			if entry.ActivatedAt != nil && entry.ExpiresAt != nil && now.Before(*entry.ExpiresAt) {
				nextExpires := entry.ExpiresAt.Add(daysToDuration(days))
				entry.ExpiresAt = &nextExpires
				totalDays := nextExpires.Sub(*entry.ActivatedAt).Hours() / 24
				entry.DurationDays = &totalDays
			} else {
				entry.DurationDays = &days
				entry.ActivatedAt = nil
				entry.ExpiresAt = nil
			}
		}
	}

	if input.ExpiresAt.Set {
		entry.ExpiresAt = normalizeTimePtr(input.ExpiresAt.Value)
		if input.ExpiresAt.Value != nil {
			entry.DurationDays = nil
			entry.ActivatedAt = nil
		}
	}

	if input.QuotaLimit.Set {
		if input.QuotaLimit.Value != nil && *input.QuotaLimit.Value < 0 {
			return ManagedAPIKey{}, fmt.Errorf("quotaLimit cannot be negative")
		}
		entry.QuotaLimit = cloneInt64Ptr(input.QuotaLimit.Value)
	}
	if input.ResetQuotaUsed {
		entry.QuotaUsed = 0
	}

	entry.UpdatedAt = now
	if err := m.saveLocked(); err != nil {
		return ManagedAPIKey{}, err
	}
	return cloneManagedAPIKey(*entry), nil
}

func (m *ManagedAPIKeyManager) Renew(id int64, input ManagedAPIKeyRenewInput) (ManagedAPIKey, error) {
	if m == nil {
		return ManagedAPIKey{}, fmt.Errorf("managed API key manager is nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.byID[id]
	if !ok || entry == nil {
		return ManagedAPIKey{}, ErrManagedAPIKeyNotFound
	}
	now := time.Now().UTC()

	if input.DurationDays != nil {
		days := *input.DurationDays
		if days <= 0 {
			return ManagedAPIKey{}, fmt.Errorf("durationDays must be greater than 0")
		}
		if entry.ActivatedAt != nil && entry.ExpiresAt != nil && now.Before(*entry.ExpiresAt) {
			nextExpires := entry.ExpiresAt.Add(daysToDuration(days))
			entry.ExpiresAt = &nextExpires
			totalDays := nextExpires.Sub(*entry.ActivatedAt).Hours() / 24
			entry.DurationDays = &totalDays
		} else {
			entry.DurationDays = &days
			entry.ActivatedAt = nil
			entry.ExpiresAt = nil
		}
	}

	if input.QuotaLimit.Set {
		if input.QuotaLimit.Value != nil && *input.QuotaLimit.Value < 0 {
			return ManagedAPIKey{}, fmt.Errorf("quotaLimit cannot be negative")
		}
		entry.QuotaLimit = cloneInt64Ptr(input.QuotaLimit.Value)
	}
	if input.QuotaIncrease != nil {
		if *input.QuotaIncrease < 0 {
			return ManagedAPIKey{}, fmt.Errorf("quotaIncrease cannot be negative")
		}
		current := int64(0)
		if entry.QuotaLimit != nil {
			current = *entry.QuotaLimit
		}
		next := current + *input.QuotaIncrease
		entry.QuotaLimit = &next
	}
	if input.ResetQuotaUsed {
		entry.QuotaUsed = 0
	}

	entry.Enabled = true
	entry.UpdatedAt = now
	if err := m.saveLocked(); err != nil {
		return ManagedAPIKey{}, err
	}
	return cloneManagedAPIKey(*entry), nil
}

func (m *ManagedAPIKeyManager) Delete(id int64) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.byID[id]
	if !ok || entry == nil {
		return false
	}
	delete(m.byID, id)
	delete(m.byKey, entry.Key)
	if err := m.saveLocked(); err != nil {
		log.WithError(err).Errorf("failed to persist managed API key deletion: id=%d", id)
	}
	return true
}

func (m *ManagedAPIKeyManager) Authenticate(apiKey string, now time.Time) ManagedAPIKeyAuthOutcome {
	outcome := ManagedAPIKeyAuthOutcome{}
	if m == nil {
		return outcome
	}
	candidate := strings.TrimSpace(apiKey)
	if candidate == "" {
		return outcome
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	m.mu.Lock()
	entry, ok := m.byKey[candidate]
	if !ok || entry == nil {
		m.mu.Unlock()
		return outcome
	}

	outcome.Matched = true
	status := entry.status(now)
	if status == ManagedAPIKeyStatusPending {
		days := entry.DurationDays
		if days != nil && *days > 0 {
			activated := now
			expires := now.Add(daysToDuration(*days))
			entry.ActivatedAt = &activated
			entry.ExpiresAt = &expires
			entry.UpdatedAt = now
			if err := m.saveLocked(); err != nil {
				log.WithError(err).Warnf("failed to persist managed API key activation: id=%d", entry.ID)
			}
			status = entry.status(now)
		}
	}

	if status != ManagedAPIKeyStatusActive {
		outcome.Key = cloneManagedAPIKey(*entry)
		outcome.Status = status
		m.mu.Unlock()
		return outcome
	}

	entry.QuotaUsed++
	usedAt := now
	entry.LastUsedAt = &usedAt
	entry.UpdatedAt = now
	if err := m.saveLocked(); err != nil {
		log.WithError(err).Warnf("failed to persist managed API key usage: id=%d", entry.ID)
	}

	outcome.Key = cloneManagedAPIKey(*entry)
	outcome.Status = ManagedAPIKeyStatusActive
	m.mu.Unlock()
	return outcome
}

func (m *ManagedAPIKeyManager) load() error {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read managed API key store: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}

	var store managedAPIKeyStore
	if err = json.Unmarshal(data, &store); err != nil {
		var legacyItems []ManagedAPIKey
		if errLegacy := json.Unmarshal(data, &legacyItems); errLegacy != nil {
			return fmt.Errorf("parse managed API key store: %w", err)
		}
		store.Items = legacyItems
	}

	maxID := int64(0)
	for i := range store.Items {
		item := normalizeManagedAPIKey(store.Items[i])
		if item.ID <= 0 || item.Key == "" {
			continue
		}
		if _, exists := m.byID[item.ID]; exists {
			continue
		}
		if _, exists := m.byKey[item.Key]; exists {
			continue
		}
		entry := item
		m.byID[item.ID] = &entry
		m.byKey[item.Key] = &entry
		if item.ID > maxID {
			maxID = item.ID
		}
	}

	m.nextID = store.NextID
	if m.nextID <= maxID {
		m.nextID = maxID + 1
	}
	if m.nextID <= 0 {
		m.nextID = 1
	}

	return nil
}

func (m *ManagedAPIKeyManager) saveLocked() error {
	store := managedAPIKeyStore{
		Version: 1,
		NextID:  m.nextID,
		Items:   make([]ManagedAPIKey, 0, len(m.byID)),
	}
	for _, key := range m.byID {
		if key == nil {
			continue
		}
		store.Items = append(store.Items, cloneManagedAPIKey(*key))
	}
	sort.Slice(store.Items, func(i, j int) bool {
		return store.Items[i].ID < store.Items[j].ID
	})

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal managed API key store: %w", err)
	}

	dir := filepath.Dir(m.filePath)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create managed API key store dir: %w", err)
	}

	tmpFile := m.filePath + ".tmp"
	if err = os.WriteFile(tmpFile, data, 0o600); err != nil {
		return fmt.Errorf("write managed API key temp file: %w", err)
	}
	if err = os.Rename(tmpFile, m.filePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("replace managed API key store: %w", err)
	}
	return nil
}

func cloneManagedAPIKey(in ManagedAPIKey) ManagedAPIKey {
	out := in
	out.CreatedAt = in.CreatedAt.UTC()
	out.UpdatedAt = in.UpdatedAt.UTC()
	out.ActivatedAt = cloneTimePtr(in.ActivatedAt)
	out.ExpiresAt = cloneTimePtr(in.ExpiresAt)
	out.DurationDays = cloneFloat64Ptr(in.DurationDays)
	out.QuotaLimit = cloneInt64Ptr(in.QuotaLimit)
	out.LastUsedAt = cloneTimePtr(in.LastUsedAt)
	return out
}

func normalizeManagedAPIKey(in ManagedAPIKey) ManagedAPIKey {
	out := cloneManagedAPIKey(in)
	out.Key = strings.TrimSpace(out.Key)
	out.Name = strings.TrimSpace(out.Name)
	if out.Name == "" {
		out.Name = fmt.Sprintf("API Key %d", out.ID)
	}
	if out.CreatedAt.IsZero() {
		out.CreatedAt = time.Now().UTC()
	}
	if out.UpdatedAt.IsZero() {
		out.UpdatedAt = out.CreatedAt
	}
	if out.DurationDays != nil && *out.DurationDays <= 0 {
		out.DurationDays = nil
	}
	if out.QuotaLimit != nil && *out.QuotaLimit < 0 {
		out.QuotaLimit = nil
	}
	if out.QuotaUsed < 0 {
		out.QuotaUsed = 0
	}
	if out.ActivatedAt != nil {
		value := out.ActivatedAt.UTC()
		out.ActivatedAt = &value
	}
	if out.ExpiresAt != nil {
		value := out.ExpiresAt.UTC()
		out.ExpiresAt = &value
	}
	if out.LastUsedAt != nil {
		value := out.LastUsedAt.UTC()
		out.LastUsedAt = &value
	}
	return out
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func normalizeTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := value.UTC()
	return &normalized
}

func cloneFloat64Ptr(value *float64) *float64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneInt64Ptr(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func daysToDuration(days float64) time.Duration {
	if days <= 0 {
		return 0
	}
	return time.Duration(days * float64(24*time.Hour))
}

func generateManagedAPIKey() (string, error) {
	buffer := make([]byte, 20)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "sk-client-" + hex.EncodeToString(buffer), nil
}
