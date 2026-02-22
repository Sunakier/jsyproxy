package store

import (
	"crypto/rand"
	"crypto/sha256"
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

	"github.com/google/uuid"
)

const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"

const (
	CacheStrategyForce          = "force"
	CacheStrategyLazy           = "lazy"
	cacheVariantDefault         = "__default__"
	cacheVariantUnknown         = "__unknown__"
	maxTrackedUAVariants        = 100
	maxCacheVariantsPerUpstream = maxTrackedUAVariants + 1
	defaultActiveUADays         = 30
)

type Upstream struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	APIEndpoint      string            `json:"api_endpoint"`
	Authorization    string            `json:"authorization"`
	RequestUserAgent string            `json:"request_user_agent"`
	Host             string            `json:"host"`
	Origin           string            `json:"origin"`
	Referer          string            `json:"referer"`
	CustomHeaders    map[string]string `json:"custom_headers,omitempty"`
	RefreshInterval  string            `json:"refresh_interval"`
	CacheStrategy    string            `json:"cache_strategy"`
	Enabled          bool              `json:"enabled"`
	CreatedAt        time.Time         `json:"created_at"`
}

type AccessKey struct {
	ID         string    `json:"id"`
	Key        string    `json:"key"`
	Name       string    `json:"name"`
	UpstreamID string    `json:"upstream_id"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
}

type ClientUpdateLog struct {
	Time        time.Time `json:"time"`
	KeyID       string    `json:"key_id"`
	Key         string    `json:"key"`
	KeyName     string    `json:"key_name"`
	UpstreamID  string    `json:"upstream_id"`
	ClientIP    string    `json:"client_ip"`
	UserAgent   string    `json:"user_agent"`
	UARule      string    `json:"ua_rule,omitempty"`
	UAVariant   string    `json:"ua_variant,omitempty"`
	UAFamily    string    `json:"ua_family,omitempty"`
	CacheBucket string    `json:"cache_bucket,omitempty"`
	CacheHit    bool      `json:"cache_hit"`
	Status      string    `json:"status"`
	Message     string    `json:"message"`
}

type UAMatchDetails struct {
	UserAgent   string
	Rule        string
	Variant     string
	Family      string
	CacheBucket string
}

type TrafficStatus struct {
	ExpiredAt      int64  `json:"expired_at"`
	UsedUpload     int64  `json:"u"`
	UsedDownload   int64  `json:"d"`
	TransferEnable int64  `json:"transfer_enable"`
	PlanName       string `json:"plan_name"`
	ResetDay       int    `json:"reset_day"`
}

type GlobalConfig struct {
	LogRetentionDays int                   `json:"log_retention_days"`
	ActiveUADays     int                   `json:"active_ua_days"`
	UANormalization  UANormalizationConfig `json:"ua_normalization"`
}

type UANormalizationConfig struct {
	Enabled            bool                  `json:"enabled"`
	UnknownPassthrough bool                  `json:"unknown_passthrough"`
	Rules              []UANormalizationRule `json:"rules"`
}

type UANormalizationRule struct {
	CanonicalClass string   `json:"canonical_class"`
	BucketKey      string   `json:"bucket_key"`
	AllContains    []string `json:"all_contains,omitempty"`
	AnyContains    []string `json:"any_contains,omitempty"`
}

type CachedSubscription struct {
	Body          []byte              `json:"-"`
	Headers       map[string][]string `json:"-"`
	StatusCode    int                 `json:"status_code"`
	UpdatedAt     time.Time           `json:"updated_at"`
	SourceURL     string              `json:"source_url"`
	TrafficStatus TrafficStatus       `json:"traffic_status"`
}

type UACacheStatus struct {
	UserAgent      string     `json:"user_agent"`
	IsDefault      bool       `json:"is_default"`
	HasCache       bool       `json:"has_cache"`
	CacheUpdatedAt *time.Time `json:"cache_updated_at,omitempty"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
	TotalRequests  int        `json:"total_requests"`
	TodayRequests  int        `json:"today_requests"`
	MonthRequests  int        `json:"month_requests"`
}

type persistedState struct {
	Upstreams []Upstream                  `json:"upstreams"`
	Keys      []AccessKey                 `json:"keys"`
	Logs      []ClientUpdateLog           `json:"logs"`
	Config    GlobalConfig                `json:"config"`
	UASeen    map[string]map[string]int64 `json:"ua_seen,omitempty"`
	Version   int                         `json:"version"`
}

type State struct {
	mu            sync.RWMutex
	upstreams     map[string]Upstream
	keys          map[string]AccessKey
	keysByToken   map[string]string
	logs          []ClientUpdateLog
	caches        map[string]map[string]*CachedSubscription
	uaSeen        map[string]map[string]time.Time
	config        GlobalConfig
	adminSessions map[string]time.Time
	dataFile      string
}

func New(dataFile string, initialKeys []string, defaultRefreshInterval string) (*State, error) {
	s := &State{
		upstreams:     make(map[string]Upstream),
		keys:          make(map[string]AccessKey),
		keysByToken:   make(map[string]string),
		logs:          make([]ClientUpdateLog, 0),
		caches:        make(map[string]map[string]*CachedSubscription),
		uaSeen:        make(map[string]map[string]time.Time),
		adminSessions: make(map[string]time.Time),
		dataFile:      dataFile,
		config:        GlobalConfig{ActiveUADays: defaultActiveUADays, UANormalization: defaultUANormalizationConfig()},
	}

	if err := s.load(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	normalizedConfig, err := normalizeGlobalConfig(s.config)
	if err != nil {
		return nil, err
	}
	s.config = normalizedConfig

	if len(s.upstreams) == 0 {
		defaultUpstream := Upstream{
			ID:               uuid.New().String(),
			Name:             "default",
			RequestUserAgent: defaultUserAgent,
			RefreshInterval:  normalizeInterval(defaultRefreshInterval),
			CacheStrategy:    CacheStrategyForce,
			Enabled:          true,
			CreatedAt:        time.Now(),
		}
		s.upstreams[defaultUpstream.ID] = defaultUpstream
	}

	defaultUpstreamID := s.getDefaultUpstreamIDLocked()

	for _, keyToken := range initialKeys {
		if keyToken == "" {
			continue
		}
		if _, exists := s.keysByToken[keyToken]; exists {
			continue
		}
		keyID := uuid.New().String()
		newKey := AccessKey{
			ID:         keyID,
			Key:        keyToken,
			Name:       "bootstrap",
			UpstreamID: defaultUpstreamID,
			Enabled:    true,
			CreatedAt:  time.Now(),
		}
		s.keys[keyID] = newKey
		s.keysByToken[keyToken] = keyID
	}

	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *State) getDefaultUpstreamIDLocked() string {
	for id := range s.upstreams {
		return id
	}
	return ""
}

func (s *State) ValidateKey(keyToken string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keyID, ok := s.keysByToken[keyToken]
	if !ok {
		return false
	}
	entry, ok := s.keys[keyID]
	return ok && entry.Enabled
}

func (s *State) GetKeyByToken(keyToken string) (AccessKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keyID, ok := s.keysByToken[keyToken]
	if !ok {
		return AccessKey{}, false
	}
	entry, ok := s.keys[keyID]
	return entry, ok
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

func (s *State) AddKey(keyToken, name, upstreamID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if keyToken == "" {
		return errors.New("key不能为空")
	}
	if _, ok := s.keysByToken[keyToken]; ok {
		return errors.New("key已存在")
	}
	if upstreamID == "" {
		upstreamID = s.getDefaultUpstreamIDLocked()
	}
	if _, ok := s.upstreams[upstreamID]; !ok {
		return errors.New("指定的上游不存在")
	}
	if name == "" {
		name = "unnamed"
	}
	keyID := uuid.New().String()
	newKey := AccessKey{
		ID:         keyID,
		Key:        keyToken,
		Name:       name,
		UpstreamID: upstreamID,
		Enabled:    true,
		CreatedAt:  time.Now(),
	}
	s.keys[keyID] = newKey
	s.keysByToken[keyToken] = keyID
	return s.saveLocked()
}

func (s *State) UpdateKey(keyID string, name string, enabled bool, upstreamID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.keys[keyID]
	if !ok {
		return errors.New("key不存在")
	}
	if upstreamID != "" {
		if _, ok := s.upstreams[upstreamID]; !ok {
			return errors.New("指定的上游不存在")
		}
		key.UpstreamID = upstreamID
	}
	if name != "" {
		key.Name = name
	}
	key.Enabled = enabled
	s.keys[keyID] = key
	return s.saveLocked()
}

func (s *State) DeleteKey(keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.keys[keyID]
	if !ok {
		return errors.New("key不存在")
	}
	if len(s.keys) == 1 {
		return errors.New("至少保留一个key")
	}
	delete(s.keys, keyID)
	delete(s.keysByToken, key.Key)
	return s.saveLocked()
}

func defaultUANormalizationConfig() UANormalizationConfig {
	return UANormalizationConfig{
		Enabled:            true,
		UnknownPassthrough: true,
		Rules: []UANormalizationRule{
			{
				CanonicalClass: "clashforandroid_premium",
				BucketKey:      "clashforandroid_premium",
				AllContains:    []string{"clashforandroid", "premium"},
			},
			{
				CanonicalClass: "clashforandroid_mihomo",
				BucketKey:      "clashforandroid_mihomo",
				AllContains:    []string{"clashforandroid", "mihomo"},
			},
			{
				CanonicalClass: "clashforandroid_meta",
				BucketKey:      "clashforandroid_meta",
				AllContains:    []string{"clashforandroid", "meta"},
			},
			{
				CanonicalClass: "clash_meta_core",
				BucketKey:      "clash_meta_core",
				AnyContains:    []string{"flclash", "clash-verge"},
			},
			{
				CanonicalClass: "v2ray_family",
				BucketKey:      "v2ray_family",
				AnyContains:    []string{"v2rayn", "v2raya", "v2rayng"},
			},
		},
	}
}

func normalizeTokens(tokens []string) []string {
	if len(tokens) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tokens))
	result := make([]string, 0, len(tokens))
	for _, token := range tokens {
		normalized := strings.ToLower(strings.TrimSpace(token))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func normalizeUANormalizationConfig(config UANormalizationConfig) (UANormalizationConfig, error) {
	if config.Rules == nil && !config.Enabled && !config.UnknownPassthrough {
		return defaultUANormalizationConfig(), nil
	}
	if config.Rules == nil {
		config.Rules = defaultUANormalizationConfig().Rules
	}
	normalizedRules := make([]UANormalizationRule, 0, len(config.Rules))
	for idx, rule := range config.Rules {
		rule.CanonicalClass = strings.TrimSpace(rule.CanonicalClass)
		rule.BucketKey = strings.TrimSpace(rule.BucketKey)
		if rule.CanonicalClass == "" {
			return UANormalizationConfig{}, fmt.Errorf("ua_normalization.rules[%d].canonical_class不能为空", idx)
		}
		if rule.BucketKey == "" {
			return UANormalizationConfig{}, fmt.Errorf("ua_normalization.rules[%d].bucket_key不能为空", idx)
		}
		rule.AllContains = normalizeTokens(rule.AllContains)
		rule.AnyContains = normalizeTokens(rule.AnyContains)
		if len(rule.AllContains) == 0 && len(rule.AnyContains) == 0 {
			return UANormalizationConfig{}, fmt.Errorf("ua_normalization.rules[%d]至少需要all_contains或any_contains", idx)
		}
		normalizedRules = append(normalizedRules, rule)
	}
	config.Rules = normalizedRules
	return config, nil
}

func normalizeGlobalConfig(config GlobalConfig) (GlobalConfig, error) {
	if config.ActiveUADays <= 0 {
		config.ActiveUADays = defaultActiveUADays
	}
	uaConfig, err := normalizeUANormalizationConfig(config.UANormalization)
	if err != nil {
		return GlobalConfig{}, err
	}
	config.UANormalization = uaConfig
	return config, nil
}

func uaRuleMatches(lowerUA string, rule UANormalizationRule) bool {
	for _, token := range rule.AllContains {
		if !strings.Contains(lowerUA, token) {
			return false
		}
	}
	if len(rule.AnyContains) == 0 {
		return true
	}
	for _, token := range rule.AnyContains {
		if strings.Contains(lowerUA, token) {
			return true
		}
	}
	return false
}

func mapRawUAToCanonicalClass(userAgent string, config UANormalizationConfig) (string, *UANormalizationRule) {
	ua := strings.TrimSpace(userAgent)
	if ua == "" {
		return cacheVariantDefault, nil
	}
	if !config.Enabled {
		return ua, nil
	}
	lowerUA := strings.ToLower(ua)
	for idx := range config.Rules {
		rule := &config.Rules[idx]
		if uaRuleMatches(lowerUA, *rule) {
			return rule.CanonicalClass, rule
		}
	}
	if config.UnknownPassthrough {
		return ua, nil
	}
	return cacheVariantUnknown, nil
}

func mapCanonicalClassToBucketKey(userAgent, canonicalClass string, matchedRule *UANormalizationRule) string {
	if canonicalClass == cacheVariantDefault {
		return cacheVariantDefault
	}
	if matchedRule != nil {
		bucket := strings.TrimSpace(matchedRule.BucketKey)
		if bucket != "" {
			return bucket
		}
	}
	if strings.TrimSpace(canonicalClass) != "" {
		return canonicalClass
	}
	ua := strings.TrimSpace(userAgent)
	if ua == "" {
		return cacheVariantDefault
	}
	return ua
}

func normalizeUAVariant(userAgent string, config UANormalizationConfig) string {
	return resolveUAMatchDetails(userAgent, config).CacheBucket
}

func resolveUAMatchDetails(userAgent string, config UANormalizationConfig) UAMatchDetails {
	ua := strings.TrimSpace(userAgent)
	canonicalClass, matchedRule := mapRawUAToCanonicalClass(ua, config)
	bucket := mapCanonicalClassToBucketKey(ua, canonicalClass, matchedRule)

	rule := canonicalClass
	if matchedRule != nil {
		rule = strings.TrimSpace(matchedRule.CanonicalClass)
	} else {
		switch {
		case canonicalClass == cacheVariantDefault:
			rule = "default"
		case canonicalClass == cacheVariantUnknown:
			rule = "unknown"
		case !config.Enabled:
			rule = "normalization_disabled"
		case ua != "" && canonicalClass == ua:
			rule = "passthrough"
		}
	}

	family := bucket
	if matchedRule != nil {
		candidate := strings.TrimSpace(matchedRule.BucketKey)
		if candidate != "" {
			family = candidate
		}
	}

	return UAMatchDetails{
		UserAgent:   ua,
		Rule:        rule,
		Variant:     canonicalClass,
		Family:      family,
		CacheBucket: bucket,
	}
}

func (s *State) normalizeUAVariantLocked(userAgent string) string {
	return normalizeUAVariant(userAgent, s.config.UANormalization)
}

func (s *State) NormalizeUAVariant(userAgent string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return normalizeUAVariant(userAgent, s.config.UANormalization)
}

func (s *State) ResolveUAMatchDetails(userAgent string) UAMatchDetails {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return resolveUAMatchDetails(userAgent, s.config.UANormalization)
}

func (s *State) SetCache(upstreamID, userAgent string, cache *CachedSubscription) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cache == nil {
		return
	}
	uaKey := s.normalizeUAVariantLocked(userAgent)
	bucket, ok := s.caches[upstreamID]
	if !ok || bucket == nil {
		bucket = make(map[string]*CachedSubscription)
		s.caches[upstreamID] = bucket
	}

	if _, exists := bucket[uaKey]; !exists && len(bucket) >= maxCacheVariantsPerUpstream {
		oldestKey := ""
		var oldestAt time.Time
		for key, item := range bucket {
			if key == cacheVariantDefault {
				continue
			}
			if item == nil {
				oldestKey = key
				break
			}
			if oldestKey == "" || item.UpdatedAt.Before(oldestAt) {
				oldestKey = key
				oldestAt = item.UpdatedAt
			}
		}
		if oldestKey == "" {
			for key := range bucket {
				oldestKey = key
				break
			}
		}
		if oldestKey != "" {
			delete(bucket, oldestKey)
		}
	}

	bucket[uaKey] = cloneCache(cache)
}

func (s *State) GetCache(upstreamID, userAgent string) (*CachedSubscription, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bucket, ok := s.caches[upstreamID]
	if !ok || bucket == nil {
		return nil, false
	}
	uaKey := s.normalizeUAVariantLocked(userAgent)
	cache, ok := bucket[uaKey]
	if !ok || cache == nil {
		return nil, false
	}
	return cloneCache(cache), true
}

func (s *State) GetLatestCache(upstreamID string) (*CachedSubscription, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bucket, ok := s.caches[upstreamID]
	if !ok || len(bucket) == 0 {
		return nil, false
	}
	var latest *CachedSubscription
	for _, cache := range bucket {
		if cache == nil {
			continue
		}
		if latest == nil || cache.UpdatedAt.After(latest.UpdatedAt) {
			latest = cache
		}
	}
	if latest == nil {
		return nil, false
	}
	return cloneCache(latest), true
}

func (s *State) CacheVariantCount(upstreamID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bucket, ok := s.caches[upstreamID]
	if !ok || bucket == nil {
		return 0
	}
	return len(bucket)
}

func (s *State) MarkUASeen(upstreamID, userAgent string) {
	if strings.TrimSpace(upstreamID) == "" {
		return
	}
	uaKey := s.NormalizeUAVariant(userAgent)
	if uaKey == cacheVariantDefault {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket, ok := s.uaSeen[upstreamID]
	if !ok || bucket == nil {
		bucket = make(map[string]time.Time)
		s.uaSeen[upstreamID] = bucket
	}
	if _, exists := bucket[uaKey]; !exists && len(bucket) >= maxTrackedUAVariants {
		oldestKey := ""
		var oldestAt time.Time
		for key, seenAt := range bucket {
			if oldestKey == "" || seenAt.Before(oldestAt) {
				oldestKey = key
				oldestAt = seenAt
			}
		}
		if oldestKey != "" {
			delete(bucket, oldestKey)
		}
	}
	bucket[uaKey] = time.Now()
}

func (s *State) ActiveUADays() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.config.ActiveUADays <= 0 {
		return defaultActiveUADays
	}
	return s.config.ActiveUADays
}

func (s *State) ListActiveUAVariants(upstreamID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	variants := map[string]struct{}{cacheVariantDefault: {}}
	activeDays := s.config.ActiveUADays
	if activeDays <= 0 {
		activeDays = defaultActiveUADays
	}
	cutoff := time.Now().AddDate(0, 0, -activeDays)

	if seenMap, ok := s.uaSeen[upstreamID]; ok && seenMap != nil {
		for uaKey, lastSeen := range seenMap {
			if lastSeen.After(cutoff) || lastSeen.Equal(cutoff) {
				variants[uaKey] = struct{}{}
			} else {
				delete(seenMap, uaKey)
			}
		}
		if len(seenMap) > maxTrackedUAVariants {
			type uaLastSeen struct {
				key string
				at  time.Time
			}
			list := make([]uaLastSeen, 0, len(seenMap))
			for key, at := range seenMap {
				list = append(list, uaLastSeen{key: key, at: at})
			}
			sort.Slice(list, func(i, j int) bool { return list[i].at.Before(list[j].at) })
			for i := 0; i < len(list)-maxTrackedUAVariants; i++ {
				delete(seenMap, list[i].key)
				delete(variants, list[i].key)
			}
		}
	}

	result := make([]string, 0, len(variants))
	for uaKey := range variants {
		if uaKey == cacheVariantDefault {
			result = append(result, "")
		} else {
			result = append(result, uaKey)
		}
	}
	sort.Strings(result)
	return result
}

func (s *State) GetUpstreamUACacheStatuses(upstreamID string) []UACacheStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())

	type counter struct {
		total int
		today int
		month int
	}
	requestStats := make(map[string]counter)
	for _, entry := range s.logs {
		if entry.UpstreamID != upstreamID {
			continue
		}
		uaKey := s.normalizeUAVariantLocked(entry.UserAgent)
		item := requestStats[uaKey]
		item.total++
		if !entry.Time.Before(todayStart) {
			item.today++
		}
		if !entry.Time.Before(monthStart) {
			item.month++
		}
		requestStats[uaKey] = item
	}

	keys := map[string]struct{}{cacheVariantDefault: {}}
	bucket := s.caches[upstreamID]
	for uaKey := range bucket {
		keys[uaKey] = struct{}{}
	}
	activeDays := s.config.ActiveUADays
	if activeDays <= 0 {
		activeDays = defaultActiveUADays
	}
	cutoff := now.AddDate(0, 0, -activeDays)
	if seenMap, ok := s.uaSeen[upstreamID]; ok && seenMap != nil {
		for uaKey, seenAt := range seenMap {
			if seenAt.After(cutoff) || seenAt.Equal(cutoff) {
				keys[uaKey] = struct{}{}
			}
		}
	}

	uaList := make([]string, 0, len(keys))
	for uaKey := range keys {
		uaList = append(uaList, uaKey)
	}
	sort.Strings(uaList)

	result := make([]UACacheStatus, 0, len(uaList))
	for _, uaKey := range uaList {
		item := UACacheStatus{IsDefault: uaKey == cacheVariantDefault}
		if item.IsDefault {
			item.UserAgent = ""
		} else {
			item.UserAgent = uaKey
		}
		if bucket != nil {
			if cache, ok := bucket[uaKey]; ok && cache != nil {
				item.HasCache = true
				cacheUpdatedAt := cache.UpdatedAt
				item.CacheUpdatedAt = &cacheUpdatedAt
			}
		}
		if seenMap, ok := s.uaSeen[upstreamID]; ok && seenMap != nil {
			if seenAt, exists := seenMap[uaKey]; exists {
				lastSeenAt := seenAt
				item.LastSeenAt = &lastSeenAt
			}
		}
		stats := requestStats[uaKey]
		item.TotalRequests = stats.total
		item.TodayRequests = stats.today
		item.MonthRequests = stats.month
		result = append(result, item)
	}

	return result
}

func (s *State) DedupeCacheVariants(upstreamID string) (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket, ok := s.caches[upstreamID]
	if !ok || bucket == nil || len(bucket) == 0 {
		return 0, 0
	}
	hashToVariant := make(map[string]string)
	removed := 0

	variantKeys := make([]string, 0, len(bucket))
	for variant := range bucket {
		variantKeys = append(variantKeys, variant)
	}
	sort.Strings(variantKeys)

	for _, variant := range variantKeys {
		cache := bucket[variant]
		if cache == nil {
			delete(bucket, variant)
			removed++
			continue
		}
		contentHash := cacheContentHash(cache)
		if _, exists := hashToVariant[contentHash]; exists {
			delete(bucket, variant)
			removed++
			continue
		}
		hashToVariant[contentHash] = variant
	}

	if seenMap, ok := s.uaSeen[upstreamID]; ok && seenMap != nil {
		for uaKey := range seenMap {
			if _, exists := bucket[uaKey]; !exists {
				delete(seenMap, uaKey)
			}
		}
	}

	return removed, len(bucket)
}

func cacheContentHash(cache *CachedSubscription) string {
	if cache == nil {
		return ""
	}
	h := sha256.New()
	_, _ = h.Write([]byte(fmt.Sprintf("%d|", cache.StatusCode)))
	if len(cache.Body) > 0 {
		_, _ = h.Write(cache.Body)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *State) AppendClientLog(entry ClientUpdateLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, entry)

	s.cleanupLogsLocked()

	return s.saveLocked()
}

func (s *State) cleanupLogsLocked() {
	const maxLogs = 10000

	if s.config.LogRetentionDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -s.config.LogRetentionDays)
		filtered := make([]ClientUpdateLog, 0, len(s.logs))
		for _, log := range s.logs {
			if log.Time.After(cutoff) {
				filtered = append(filtered, log)
			}
		}
		s.logs = filtered
	}

	if len(s.logs) > maxLogs {
		s.logs = s.logs[len(s.logs)-maxLogs:]
	}
}

type LogPage struct {
	Logs       []ClientUpdateLog `json:"logs"`
	Page       int               `json:"page"`
	PageSize   int               `json:"page_size"`
	TotalCount int               `json:"total_count"`
	TotalPages int               `json:"total_pages"`
}

func (s *State) ListLogsPaginated(page, pageSize int) LogPage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}

	total := len(s.logs)
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}

	startIdx := total - (page * pageSize)
	endIdx := startIdx + pageSize

	if endIdx > total {
		endIdx = total
	}
	if startIdx < 0 {
		startIdx = 0
	}

	result := make([]ClientUpdateLog, 0, endIdx-startIdx)
	for i := endIdx - 1; i >= startIdx; i-- {
		result = append(result, s.logs[i])
	}

	return LogPage{
		Logs:       result,
		Page:       page,
		PageSize:   pageSize,
		TotalCount: total,
		TotalPages: totalPages,
	}
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

func (s *State) GetGlobalConfig() GlobalConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func (s *State) UpdateGlobalConfig(next GlobalConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalized, err := normalizeGlobalConfig(next)
	if err != nil {
		return err
	}
	oldConfig := s.config
	s.config = normalized
	if err := s.saveLocked(); err != nil {
		s.config = oldConfig
		return err
	}
	return nil
}

func (s *State) ListUpstreams() []Upstream {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]Upstream, 0, len(s.upstreams))
	for _, u := range s.upstreams {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	return list
}

func (s *State) GetUpstream(id string) (Upstream, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.upstreams[id]
	return u, ok
}

func (s *State) AddUpstream(u Upstream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.Name == "" {
		return errors.New("上游名称不能为空")
	}
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	if u.CacheStrategy == "" {
		u.CacheStrategy = CacheStrategyForce
	}
	if u.RefreshInterval == "" {
		u.RefreshInterval = "10m"
	}
	if u.RequestUserAgent == "" {
		u.RequestUserAgent = defaultUserAgent
	}
	u.RefreshInterval = normalizeInterval(u.RefreshInterval)
	u.CreatedAt = time.Now()
	u.Enabled = true
	s.upstreams[u.ID] = u
	return s.saveLocked()
}

func (s *State) UpdateUpstream(u Upstream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.upstreams[u.ID]; !ok {
		return errors.New("上游不存在")
	}
	if u.RefreshInterval == "" {
		u.RefreshInterval = "10m"
	}
	if u.RequestUserAgent == "" {
		u.RequestUserAgent = defaultUserAgent
	}
	u.RefreshInterval = normalizeInterval(u.RefreshInterval)
	s.upstreams[u.ID] = u
	return s.saveLocked()
}

func (s *State) DeleteUpstream(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.upstreams[id]; !ok {
		return errors.New("上游不存在")
	}
	if len(s.upstreams) == 1 {
		return errors.New("至少保留一个上游")
	}
	for _, key := range s.keys {
		if key.UpstreamID == id {
			return errors.New("该上游还有关联的Key，请先删除或迁移这些Key")
		}
	}
	delete(s.upstreams, id)
	delete(s.caches, id)
	delete(s.uaSeen, id)
	return s.saveLocked()
}

func (s *State) GetUpstreamRefreshInterval(upstreamID string) time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.upstreams[upstreamID]
	if !ok {
		return 10 * time.Minute
	}
	d, err := time.ParseDuration(normalizeInterval(u.RefreshInterval))
	if err != nil || d <= 0 {
		return 10 * time.Minute
	}
	return d
}

func (s *State) IsCacheExpired(upstreamID, userAgent string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.upstreams[upstreamID]
	if !ok {
		return true
	}
	bucket, ok := s.caches[upstreamID]
	if !ok || bucket == nil {
		return true
	}
	cache, ok := bucket[s.normalizeUAVariantLocked(userAgent)]
	if !ok || cache == nil {
		return true
	}
	intervalRaw := normalizeInterval(u.RefreshInterval)
	interval, err := time.ParseDuration(intervalRaw)
	if err != nil || interval <= 0 {
		interval = 10 * time.Minute
	}
	if u.CacheStrategy == CacheStrategyLazy {
		return time.Since(cache.UpdatedAt) > interval
	}
	return false
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

	for _, u := range persisted.Upstreams {
		s.upstreams[u.ID] = u
	}

	for _, key := range persisted.Keys {
		s.keys[key.ID] = key
		s.keysByToken[key.Key] = key.ID
	}

	s.logs = persisted.Logs
	normalizedConfig, err := normalizeGlobalConfig(persisted.Config)
	if err != nil {
		return err
	}
	s.config = normalizedConfig
	if persisted.UASeen != nil {
		s.uaSeen = make(map[string]map[string]time.Time, len(persisted.UASeen))
		for upstreamID, variants := range persisted.UASeen {
			if variants == nil {
				continue
			}
			mapped := make(map[string]time.Time, len(variants))
			for uaKey, unix := range variants {
				if unix <= 0 {
					continue
				}
				mapped[uaKey] = time.Unix(unix, 0)
			}
			if len(mapped) > 0 {
				s.uaSeen[upstreamID] = mapped
			}
		}
	}
	return nil
}

func (s *State) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.dataFile), 0o700); err != nil {
		return err
	}

	upstreams := make([]Upstream, 0, len(s.upstreams))
	for _, u := range s.upstreams {
		upstreams = append(upstreams, u)
	}

	keys := make([]AccessKey, 0, len(s.keys))
	for _, key := range s.keys {
		keys = append(keys, key)
	}

	persisted := persistedState{
		Upstreams: upstreams,
		Keys:      keys,
		Logs:      s.logs,
		Config:    s.config,
		Version:   3,
	}
	if len(s.uaSeen) > 0 {
		persisted.UASeen = make(map[string]map[string]int64, len(s.uaSeen))
		for upstreamID, variants := range s.uaSeen {
			if variants == nil {
				continue
			}
			mapped := make(map[string]int64, len(variants))
			for uaKey, seenAt := range variants {
				if seenAt.IsZero() {
					continue
				}
				mapped[uaKey] = seenAt.Unix()
			}
			if len(mapped) > 0 {
				persisted.UASeen[upstreamID] = mapped
			}
		}
	}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.dataFile, data, 0o600)
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
