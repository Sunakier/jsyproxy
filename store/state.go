package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"

type AccessKey struct {
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type ClientUpdateLog struct {
	Time      time.Time `json:"time"`
	Key       string    `json:"key"`
	ClientIP  string    `json:"client_ip"`
	UserAgent string    `json:"user_agent"`
	CacheHit  bool      `json:"cache_hit"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
}

type TrafficStatus struct {
	ExpiredAt      int64  `json:"expired_at"`
	UsedUpload     int64  `json:"u"`
	UsedDownload   int64  `json:"d"`
	TransferEnable int64  `json:"transfer_enable"`
	PlanName       string `json:"plan_name"`
	ResetDay       int    `json:"reset_day"`
}

type UpstreamConfig struct {
	UpstreamURL      string `json:"upstream_url"`
	Authorization    string `json:"authorization"`
	RequestUserAgent string `json:"request_user_agent"`
	Host             string `json:"host"`
	Origin           string `json:"origin"`
	Referer          string `json:"referer"`
	RefreshInterval  string `json:"refresh_interval"`
}

type CachedSubscription struct {
	Body          []byte              `json:"-"`
	Headers       map[string][]string `json:"-"`
	StatusCode    int                 `json:"status_code"`
	UpdatedAt     time.Time           `json:"updated_at"`
	SourceURL     string              `json:"source_url"`
	TrafficStatus TrafficStatus       `json:"traffic_status"`
}

type persistedState struct {
	Keys    []AccessKey       `json:"keys"`
	Logs    []ClientUpdateLog `json:"logs"`
	Config  UpstreamConfig    `json:"config"`
	Version int               `json:"version"`
}

type State struct {
	mu            sync.RWMutex
	keys          map[string]AccessKey
	logs          []ClientUpdateLog
	cache         *CachedSubscription
	config        UpstreamConfig
	adminSessions map[string]time.Time
	dataFile      string
}

func New(dataFile string, initialKeys []string, defaultRefreshInterval string) (*State, error) {
	s := &State{
		keys:          make(map[string]AccessKey),
		logs:          make([]ClientUpdateLog, 0),
		adminSessions: make(map[string]time.Time),
		dataFile:      dataFile,
		config: UpstreamConfig{
			RequestUserAgent: defaultUserAgent,
			RefreshInterval:  normalizeInterval(defaultRefreshInterval),
		},
	}

	if err := s.load(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range initialKeys {
		if _, ok := s.keys[key]; ok {
			continue
		}
		s.keys[key] = AccessKey{
			Key:       key,
			Name:      "bootstrap",
			Enabled:   true,
			CreatedAt: time.Now(),
		}
	}

	if s.config.RequestUserAgent == "" {
		s.config.RequestUserAgent = defaultUserAgent
	}
	s.config.RefreshInterval = normalizeInterval(s.config.RefreshInterval)

	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *State) ValidateKey(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.keys[key]
	return ok && entry.Enabled
}

func (s *State) ListKeys() []AccessKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]AccessKey, 0, len(s.keys))
	for _, key := range s.keys {
		list = append(list, key)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	return list
}

func (s *State) AddKey(key, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == "" {
		return errors.New("key不能为空")
	}
	if _, ok := s.keys[key]; ok {
		return errors.New("key已存在")
	}
	if name == "" {
		name = "unnamed"
	}
	s.keys[key] = AccessKey{Key: key, Name: name, Enabled: true, CreatedAt: time.Now()}
	return s.saveLocked()
}

func (s *State) DeleteKey(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[key]; !ok {
		return errors.New("key不存在")
	}
	if len(s.keys) == 1 {
		return errors.New("至少保留一个key")
	}
	delete(s.keys, key)
	return s.saveLocked()
}

func (s *State) SetCache(cache *CachedSubscription) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache = cache
}

func (s *State) GetCache() (*CachedSubscription, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cache == nil {
		return nil, false
	}
	return cloneCache(s.cache), true
}

func (s *State) AppendClientLog(entry ClientUpdateLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, entry)
	const maxLogs = 1000
	if len(s.logs) > maxLogs {
		s.logs = s.logs[len(s.logs)-maxLogs:]
	}
	return s.saveLocked()
}

func (s *State) ListLogs(limit int) []ClientUpdateLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.logs) {
		limit = len(s.logs)
	}
	result := make([]ClientUpdateLog, 0, limit)
	for i := len(s.logs) - 1; i >= 0 && len(result) < limit; i-- {
		result = append(result, s.logs[i])
	}
	return result
}

func (s *State) LogCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.logs)
}

func (s *State) GetConfig() UpstreamConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func (s *State) UpdateConfig(next UpstreamConfig) error {
	next.RefreshInterval = normalizeInterval(next.RefreshInterval)
	if next.RequestUserAgent == "" {
		next.RequestUserAgent = defaultUserAgent
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = next
	return s.saveLocked()
}

func (s *State) GetRefreshInterval() time.Duration {
	s.mu.RLock()
	raw := s.config.RefreshInterval
	s.mu.RUnlock()
	d, err := time.ParseDuration(normalizeInterval(raw))
	if err != nil || d <= 0 {
		return 10 * time.Minute
	}
	return d
}

func (s *State) CreateAdminSession() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adminSessions[token] = time.Now().Add(24 * time.Hour)
	return token, nil
}

func (s *State) ValidateAdminSession(token string) bool {
	if token == "" {
		return false
	}
	s.mu.RLock()
	expiresAt, ok := s.adminSessions[token]
	s.mu.RUnlock()
	if !ok || time.Now().After(expiresAt) {
		if ok {
			s.mu.Lock()
			delete(s.adminSessions, token)
			s.mu.Unlock()
		}
		return false
	}
	return true
}

func (s *State) DeleteAdminSession(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.adminSessions, token)
}

func (s *State) load() error {
	if _, err := os.Stat(s.dataFile); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	content, err := os.ReadFile(s.dataFile)
	if err != nil {
		return err
	}
	var persisted persistedState
	if err := json.Unmarshal(content, &persisted); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range persisted.Keys {
		s.keys[key.Key] = key
	}
	s.logs = persisted.Logs
	s.config = persisted.Config
	return nil
}

func (s *State) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.dataFile), 0o755); err != nil {
		return err
	}
	keys := make([]AccessKey, 0, len(s.keys))
	for _, key := range s.keys {
		keys = append(keys, key)
	}
	persisted := persistedState{Keys: keys, Logs: s.logs, Config: s.config, Version: 2}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.dataFile, data, 0o644)
}

func cloneCache(src *CachedSubscription) *CachedSubscription {
	if src == nil {
		return nil
	}
	return &CachedSubscription{
		Body:          append([]byte(nil), src.Body...),
		Headers:       cloneHeaders(src.Headers),
		StatusCode:    src.StatusCode,
		UpdatedAt:     src.UpdatedAt,
		SourceURL:     src.SourceURL,
		TrafficStatus: src.TrafficStatus,
	}
}

func cloneHeaders(src map[string][]string) map[string][]string {
	if src == nil {
		return nil
	}
	result := make(map[string][]string, len(src))
	for k, values := range src {
		result[k] = append([]string(nil), values...)
	}
	return result
}

func normalizeInterval(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "10m"
	}
	if _, err := time.ParseDuration(trimmed); err == nil {
		return trimmed
	}
	if onlyDigits(trimmed) {
		return trimmed + "s"
	}
	return "10m"
}

func onlyDigits(raw string) bool {
	if raw == "" {
		return false
	}
	for _, r := range raw {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
