package management

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	configaccess "github.com/router-for-me/CLIProxyAPI/v6/internal/access/config_access"
)

type managedAPIKeyResponse struct {
	ID            int64      `json:"id"`
	Key           string     `json:"key"`
	Name          string     `json:"name"`
	Enabled       bool       `json:"enabled"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
	ActivatedAt   *time.Time `json:"activatedAt,omitempty"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
	DurationDays  *float64   `json:"durationDays,omitempty"`
	QuotaLimit    *int64     `json:"quotaLimit,omitempty"`
	SpendingLimit *int64     `json:"spendingLimit,omitempty"`
	QuotaUsed     int64      `json:"quotaUsed"`
	LastUsedAt    *time.Time `json:"lastUsedAt,omitempty"`
}

func (h *Handler) GetServerInfo(c *gin.Context) {
	baseURL := inferRequestBaseURL(c.Request)
	masterKey := ""
	if h != nil && h.cfg != nil {
		for _, key := range h.cfg.APIKeys {
			trimmed := strings.TrimSpace(key)
			if trimmed == "" {
				continue
			}
			masterKey = trimmed
			break
		}
	}

	var master any
	if masterKey != "" {
		master = masterKey
	}

	c.JSON(http.StatusOK, gin.H{
		"baseURL":        baseURL,
		"base-url":       baseURL,
		"masterApiKey":   master,
		"master-api-key": master,
	})
}

func (h *Handler) ListManagedAPIKeys(c *gin.Context) {
	manager := h.managedAPIKeyManager(c)
	if manager == nil {
		return
	}

	items := manager.List()
	now := time.Now().UTC()
	result := make([]managedAPIKeyResponse, 0, len(items))
	for _, item := range items {
		result = append(result, toManagedAPIKeyResponse(item, now))
	}

	c.JSON(http.StatusOK, gin.H{
		"items": result,
		"count": len(result),
	})
}

func (h *Handler) CreateManagedAPIKey(c *gin.Context) {
	manager := h.managedAPIKeyManager(c)
	if manager == nil {
		return
	}
	body, ok := parseBodyMap(c)
	if !ok {
		return
	}

	name, err := parseRequiredString(body, "name")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	expiresAt, err := parseOptionalTime(body, "expiresAt", "expires-at")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid expiresAt: %v", err)})
		return
	}
	durationDays, err := parseOptionalFloat64(body, "durationDays", "duration-days")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid durationDays: %v", err)})
		return
	}
	quotaLimit, err := parseOptionalInt64(body, "quotaLimit", "quota-limit", "spendingLimit", "spending-limit")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid quotaLimit: %v", err)})
		return
	}
	enabled, err := parseOptionalBool(body, "enabled")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid enabled: %v", err)})
		return
	}
	rawKey, err := parseOptionalString(body, "key", "apiKey", "api-key")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid key: %v", err)})
		return
	}

	input := configaccess.ManagedAPIKeyCreateInput{
		Name:   name,
		RawKey: rawKey,
	}
	if expiresAt.Set {
		input.ExpiresAt = expiresAt.Value
	}
	if durationDays.Set {
		input.DurationDays = durationDays.Value
	}
	if quotaLimit.Set {
		input.QuotaLimit = quotaLimit.Value
	}
	if enabled.Set {
		value := enabled.Value
		input.Enabled = &value
	}

	created, err := manager.Create(input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.refreshAccessProviders()

	c.JSON(http.StatusCreated, toManagedAPIKeyResponse(created, time.Now().UTC()))
}

func (h *Handler) PatchManagedAPIKey(c *gin.Context) {
	manager := h.managedAPIKeyManager(c)
	if manager == nil {
		return
	}
	id, ok := parsePathID(c)
	if !ok {
		return
	}
	body, parsed := parseBodyMap(c)
	if !parsed {
		return
	}

	name, err := parseOptionalStringField(body, "name")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid name: %v", err)})
		return
	}
	enabled, err := parseOptionalBool(body, "enabled")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid enabled: %v", err)})
		return
	}
	expiresAt, err := parseOptionalTime(body, "expiresAt", "expires-at")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid expiresAt: %v", err)})
		return
	}
	durationDays, err := parseOptionalFloat64(body, "durationDays", "duration-days")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid durationDays: %v", err)})
		return
	}
	quotaLimit, err := parseOptionalInt64(body, "quotaLimit", "quota-limit", "spendingLimit", "spending-limit")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid quotaLimit: %v", err)})
		return
	}
	resetQuotaUsed := parseBoolDefault(body, false, "resetQuotaUsed", "reset-quota-used")

	input := configaccess.ManagedAPIKeyUpdateInput{
		Name:           name,
		ExpiresAt:      expiresAt,
		DurationDays:   durationDays,
		QuotaLimit:     quotaLimit,
		ResetQuotaUsed: resetQuotaUsed,
	}
	if enabled.Set {
		input.Enabled = configaccess.OptionalBool{Set: true, Value: enabled.Value}
	}

	updated, err := manager.Update(id, input)
	if err != nil {
		if err == configaccess.ErrManagedAPIKeyNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "managed API key not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.refreshAccessProviders()

	c.JSON(http.StatusOK, toManagedAPIKeyResponse(updated, time.Now().UTC()))
}

func (h *Handler) RenewManagedAPIKey(c *gin.Context) {
	manager := h.managedAPIKeyManager(c)
	if manager == nil {
		return
	}
	id, ok := parsePathID(c)
	if !ok {
		return
	}
	body, parsed := parseBodyMap(c)
	if !parsed {
		return
	}

	durationDays, err := parseOptionalFloat64(body, "durationDays", "duration-days")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid durationDays: %v", err)})
		return
	}
	quotaIncrease, err := parseOptionalInt64(body, "quotaIncrease", "quota-increase")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid quotaIncrease: %v", err)})
		return
	}
	quotaLimit, err := parseOptionalInt64(body, "quotaLimit", "quota-limit", "spendingLimit", "spending-limit")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid quotaLimit: %v", err)})
		return
	}
	resetQuotaUsed := parseBoolDefault(body, true, "resetQuotaUsed", "reset-quota-used")

	input := configaccess.ManagedAPIKeyRenewInput{
		QuotaLimit:     quotaLimit,
		ResetQuotaUsed: resetQuotaUsed,
	}
	if durationDays.Set {
		input.DurationDays = durationDays.Value
	}
	if quotaIncrease.Set {
		input.QuotaIncrease = quotaIncrease.Value
	}

	renewed, err := manager.Renew(id, input)
	if err != nil {
		if err == configaccess.ErrManagedAPIKeyNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "managed API key not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.refreshAccessProviders()

	c.JSON(http.StatusOK, toManagedAPIKeyResponse(renewed, time.Now().UTC()))
}

func (h *Handler) DeleteManagedAPIKey(c *gin.Context) {
	manager := h.managedAPIKeyManager(c)
	if manager == nil {
		return
	}
	id, ok := parsePathID(c)
	if !ok {
		return
	}

	if !manager.Delete(id) {
		c.JSON(http.StatusNotFound, gin.H{"error": "managed API key not found"})
		return
	}
	h.refreshAccessProviders()

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) managedAPIKeyManager(c *gin.Context) *configaccess.ManagedAPIKeyManager {
	manager := configaccess.GetManagedAPIKeyManager()
	if manager != nil {
		return manager
	}
	if h != nil && h.cfg != nil {
		configaccess.Register(h.cfg)
		manager = configaccess.GetManagedAPIKeyManager()
		if manager != nil {
			return manager
		}
	}
	c.JSON(http.StatusServiceUnavailable, gin.H{"error": "managed API key service unavailable"})
	return nil
}

func parsePathID(c *gin.Context) (int64, bool) {
	raw := strings.TrimSpace(c.Param("id"))
	if raw == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return 0, false
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return 0, false
	}
	return id, true
}

func parseBodyMap(c *gin.Context) (map[string]json.RawMessage, bool) {
	var body map[string]json.RawMessage
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return nil, false
	}
	if len(body) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "empty body"})
		return nil, false
	}
	return body, true
}

func parseRequiredString(body map[string]json.RawMessage, keys ...string) (string, error) {
	value, err := parseStringField(body, keys...)
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is required", firstFieldName(keys...))
	}
	return value, nil
}

func parseOptionalString(body map[string]json.RawMessage, keys ...string) (string, error) {
	field, err := parseOptionalStringField(body, keys...)
	if err != nil {
		return "", err
	}
	if !field.Set {
		return "", nil
	}
	return field.Value, nil
}

func parseOptionalStringField(body map[string]json.RawMessage, keys ...string) (configaccess.OptionalString, error) {
	raw, ok := readField(body, keys...)
	if !ok {
		return configaccess.OptionalString{}, nil
	}
	if isJSONNull(raw) {
		return configaccess.OptionalString{Set: true, Value: ""}, nil
	}
	value, err := parseStringRaw(raw)
	if err != nil {
		return configaccess.OptionalString{}, err
	}
	return configaccess.OptionalString{Set: true, Value: value}, nil
}

func parseStringField(body map[string]json.RawMessage, keys ...string) (string, error) {
	raw, ok := readField(body, keys...)
	if !ok {
		return "", fmt.Errorf("%s is required", firstFieldName(keys...))
	}
	if isJSONNull(raw) {
		return "", fmt.Errorf("%s cannot be null", firstFieldName(keys...))
	}
	return parseStringRaw(raw)
}

func parseOptionalBool(body map[string]json.RawMessage, keys ...string) (configaccess.OptionalBool, error) {
	raw, ok := readField(body, keys...)
	if !ok {
		return configaccess.OptionalBool{}, nil
	}
	if isJSONNull(raw) {
		return configaccess.OptionalBool{}, nil
	}
	value, err := parseBoolRaw(raw)
	if err != nil {
		return configaccess.OptionalBool{}, err
	}
	return configaccess.OptionalBool{Set: true, Value: value}, nil
}

func parseOptionalTime(body map[string]json.RawMessage, keys ...string) (configaccess.OptionalTime, error) {
	raw, ok := readField(body, keys...)
	if !ok {
		return configaccess.OptionalTime{}, nil
	}
	if isJSONNull(raw) {
		return configaccess.OptionalTime{Set: true, Value: nil}, nil
	}
	value, err := parseTimeRaw(raw)
	if err != nil {
		return configaccess.OptionalTime{}, err
	}
	return configaccess.OptionalTime{Set: true, Value: &value}, nil
}

func parseOptionalFloat64(body map[string]json.RawMessage, keys ...string) (configaccess.OptionalFloat64, error) {
	raw, ok := readField(body, keys...)
	if !ok {
		return configaccess.OptionalFloat64{}, nil
	}
	if isJSONNull(raw) {
		return configaccess.OptionalFloat64{Set: true, Value: nil}, nil
	}
	value, err := parseFloat64Raw(raw)
	if err != nil {
		return configaccess.OptionalFloat64{}, err
	}
	return configaccess.OptionalFloat64{Set: true, Value: &value}, nil
}

func parseOptionalInt64(body map[string]json.RawMessage, keys ...string) (configaccess.OptionalInt64, error) {
	raw, ok := readField(body, keys...)
	if !ok {
		return configaccess.OptionalInt64{}, nil
	}
	if isJSONNull(raw) {
		return configaccess.OptionalInt64{Set: true, Value: nil}, nil
	}
	value, err := parseInt64Raw(raw)
	if err != nil {
		return configaccess.OptionalInt64{}, err
	}
	return configaccess.OptionalInt64{Set: true, Value: &value}, nil
}

func parseBoolDefault(body map[string]json.RawMessage, fallback bool, keys ...string) bool {
	field, err := parseOptionalBool(body, keys...)
	if err != nil || !field.Set {
		return fallback
	}
	return field.Value
}

func readField(body map[string]json.RawMessage, keys ...string) (json.RawMessage, bool) {
	for _, key := range keys {
		if value, ok := body[key]; ok {
			return value, true
		}
	}
	return nil, false
}

func parseStringRaw(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("must be a string")
	}
	return value, nil
}

func parseBoolRaw(raw json.RawMessage) (bool, error) {
	var value bool
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		normalized := strings.ToLower(strings.TrimSpace(text))
		if normalized == "true" {
			return true, nil
		}
		if normalized == "false" {
			return false, nil
		}
	}
	return false, fmt.Errorf("must be a boolean")
}

func parseInt64Raw(raw json.RawMessage) (int64, error) {
	var intValue int64
	if err := json.Unmarshal(raw, &intValue); err == nil {
		return intValue, nil
	}
	var floatValue float64
	if err := json.Unmarshal(raw, &floatValue); err == nil {
		if math.Trunc(floatValue) != floatValue {
			return 0, fmt.Errorf("must be an integer")
		}
		return int64(floatValue), nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		parsed, parseErr := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
		if parseErr != nil {
			return 0, fmt.Errorf("must be an integer")
		}
		return parsed, nil
	}
	return 0, fmt.Errorf("must be an integer")
}

func parseFloat64Raw(raw json.RawMessage) (float64, error) {
	var value float64
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		parsed, parseErr := strconv.ParseFloat(strings.TrimSpace(text), 64)
		if parseErr != nil {
			return 0, fmt.Errorf("must be a number")
		}
		return parsed, nil
	}
	return 0, fmt.Errorf("must be a number")
}

func parseTimeRaw(raw json.RawMessage) (time.Time, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		trimmed := strings.TrimSpace(text)
		if trimmed == "" {
			return time.Time{}, fmt.Errorf("must be RFC3339 time")
		}
		parsed, parseErr := time.Parse(time.RFC3339, trimmed)
		if parseErr != nil {
			parsed, parseErr = time.Parse(time.RFC3339Nano, trimmed)
		}
		if parseErr != nil {
			return time.Time{}, fmt.Errorf("must be RFC3339 time")
		}
		return parsed.UTC(), nil
	}

	var parsed time.Time
	if err := json.Unmarshal(raw, &parsed); err == nil {
		return parsed.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("must be RFC3339 time")
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func firstFieldName(keys ...string) string {
	if len(keys) == 0 {
		return "field"
	}
	return keys[0]
}

func inferRequestBaseURL(r *http.Request) string {
	if r == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwardedProto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwardedProto != "" {
		parts := strings.Split(forwardedProto, ",")
		if len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
			scheme = strings.TrimSpace(parts[0])
		}
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

func toManagedAPIKeyResponse(item configaccess.ManagedAPIKey, now time.Time) managedAPIKeyResponse {
	out := managedAPIKeyResponse{
		ID:            item.ID,
		Key:           item.Key,
		Name:          item.Name,
		Enabled:       item.Enabled,
		Status:        item.Status(now),
		CreatedAt:     item.CreatedAt,
		UpdatedAt:     item.UpdatedAt,
		ActivatedAt:   cloneTime(item.ActivatedAt),
		ExpiresAt:     cloneTime(item.ExpiresAt),
		DurationDays:  cloneFloat(item.DurationDays),
		QuotaLimit:    cloneInt(item.QuotaLimit),
		SpendingLimit: cloneInt(item.QuotaLimit),
		QuotaUsed:     item.QuotaUsed,
		LastUsedAt:    cloneTime(item.LastUsedAt),
	}
	return out
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func cloneFloat(value *float64) *float64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneInt(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
