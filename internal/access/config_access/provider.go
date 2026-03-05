package configaccess

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v6/sdk/access"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
	log "github.com/sirupsen/logrus"
)

var managedAPIKeyState struct {
	mu       sync.RWMutex
	filePath string
	manager  *ManagedAPIKeyManager
}

// Register ensures the config-access provider is available to the access manager.
func Register(cfg *sdkconfig.Config) {
	if cfg == nil {
		setManagedAPIKeyManager("", nil)
		sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey)
		return
	}

	keys := normalizeKeys(cfg.APIKeys)
	manager := ensureManagedAPIKeyManager(cfg)

	if len(keys) == 0 && (manager == nil || !manager.HasKeys()) {
		sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey)
		return
	}

	sdkaccess.RegisterProvider(
		sdkaccess.AccessProviderTypeConfigAPIKey,
		newProvider(sdkaccess.DefaultAccessProviderName, keys, manager),
	)
}

func GetManagedAPIKeyManager() *ManagedAPIKeyManager {
	managedAPIKeyState.mu.RLock()
	manager := managedAPIKeyState.manager
	managedAPIKeyState.mu.RUnlock()
	return manager
}

func ensureManagedAPIKeyManager(cfg *sdkconfig.Config) *ManagedAPIKeyManager {
	if cfg == nil {
		return nil
	}
	authDir := strings.TrimSpace(cfg.AuthDir)
	if resolved, err := util.ResolveAuthDir(authDir); err == nil {
		authDir = resolved
	} else if authDir != "" {
		log.WithError(err).Warnf("failed to resolve auth-dir %q for managed API keys", authDir)
	}

	filePath := ManagedAPIKeyFilePath(authDir)
	if filePath == "" {
		return nil
	}

	managedAPIKeyState.mu.RLock()
	if managedAPIKeyState.filePath == filePath && managedAPIKeyState.manager != nil {
		manager := managedAPIKeyState.manager
		managedAPIKeyState.mu.RUnlock()
		return manager
	}
	currentManager := managedAPIKeyState.manager
	managedAPIKeyState.mu.RUnlock()

	manager, err := NewManagedAPIKeyManager(filePath)
	if err != nil {
		log.WithError(err).Errorf("failed to initialize managed API key store at %s", filePath)
		if currentManager != nil {
			return currentManager
		}
		return nil
	}
	setManagedAPIKeyManager(filePath, manager)
	return manager
}

func setManagedAPIKeyManager(filePath string, manager *ManagedAPIKeyManager) {
	managedAPIKeyState.mu.Lock()
	managedAPIKeyState.filePath = filePath
	managedAPIKeyState.manager = manager
	managedAPIKeyState.mu.Unlock()
}

type provider struct {
	name    string
	keys    map[string]struct{}
	managed *ManagedAPIKeyManager
}

func newProvider(name string, keys []string, managed *ManagedAPIKeyManager) *provider {
	providerName := strings.TrimSpace(name)
	if providerName == "" {
		providerName = sdkaccess.DefaultAccessProviderName
	}
	keySet := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		keySet[key] = struct{}{}
	}
	return &provider{name: providerName, keys: keySet, managed: managed}
}

func (p *provider) Identifier() string {
	if p == nil || p.name == "" {
		return sdkaccess.DefaultAccessProviderName
	}
	return p.name
}

func (p *provider) Authenticate(_ context.Context, r *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	if p == nil {
		return nil, sdkaccess.NewNotHandledError()
	}
	if len(p.keys) == 0 && (p.managed == nil || !p.managed.HasKeys()) {
		return nil, sdkaccess.NewNotHandledError()
	}
	authHeader := r.Header.Get("Authorization")
	authHeaderGoogle := r.Header.Get("X-Goog-Api-Key")
	authHeaderAnthropic := r.Header.Get("X-Api-Key")
	authHeaderAPIKey := r.Header.Get("Api-Key")
	queryKey := ""
	queryAuthToken := ""
	if r.URL != nil {
		queryKey = r.URL.Query().Get("key")
		queryAuthToken = r.URL.Query().Get("auth_token")
	}
	if authHeader == "" && authHeaderGoogle == "" && authHeaderAnthropic == "" && authHeaderAPIKey == "" && queryKey == "" && queryAuthToken == "" {
		return nil, sdkaccess.NewNoCredentialsError()
	}

	apiKey := extractBearerToken(authHeader)

	candidates := []struct {
		value  string
		source string
	}{
		{apiKey, "authorization"},
		{authHeaderGoogle, "x-goog-api-key"},
		{authHeaderAnthropic, "x-api-key"},
		{authHeaderAPIKey, "api-key"},
		{queryKey, "query-key"},
		{queryAuthToken, "query-auth-token"},
	}

	sawDisabled := false
	sawExpired := false
	sawQuotaReached := false

	for _, candidate := range candidates {
		if candidate.value == "" {
			continue
		}
		if _, ok := p.keys[candidate.value]; ok {
			return &sdkaccess.Result{
				Provider:  p.Identifier(),
				Principal: candidate.value,
				Metadata: map[string]string{
					"source":   candidate.source,
					"key_type": "static",
				},
			}, nil
		}
		if p.managed == nil {
			continue
		}

		outcome := p.managed.Authenticate(candidate.value, time.Now().UTC())
		if !outcome.Matched {
			continue
		}

		switch outcome.Status {
		case ManagedAPIKeyStatusActive:
			metadata := map[string]string{
				"source":         candidate.source,
				"key_type":       "managed",
				"managed_key_id": strconv.FormatInt(outcome.Key.ID, 10),
				"managed_status": outcome.Status,
			}
			if outcome.Key.Name != "" {
				metadata["managed_key_name"] = outcome.Key.Name
			}
			return &sdkaccess.Result{
				Provider:  p.Identifier(),
				Principal: candidate.value,
				Metadata:  metadata,
			}, nil
		case ManagedAPIKeyStatusDisabled:
			sawDisabled = true
		case ManagedAPIKeyStatusExpired:
			sawExpired = true
		case ManagedAPIKeyStatusQuotaReached:
			sawQuotaReached = true
		}
	}

	if sawQuotaReached {
		return nil, sdkaccess.NewQuotaExceededError()
	}
	if sawExpired {
		return nil, sdkaccess.NewExpiredCredentialError()
	}
	if sawDisabled {
		return nil, sdkaccess.NewDisabledCredentialError()
	}

	return nil, sdkaccess.NewInvalidCredentialError()
}

func extractBearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return header
	}
	if strings.ToLower(parts[0]) != "bearer" {
		return header
	}
	return strings.TrimSpace(parts[1])
}

func normalizeKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		if _, exists := seen[trimmedKey]; exists {
			continue
		}
		seen[trimmedKey] = struct{}{}
		normalized = append(normalized, trimmedKey)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}
