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
	"golang.org/x/crypto/bcrypt"
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
	AdminRoleSuperAdmin         = "super_admin"
	AdminRoleOperator           = "operator"
	AdminRoleViewer             = "viewer"
	PermissionAdminRead         = "admin.read"
	PermissionAdminWrite        = "admin.write"
	PermissionSettingsWrite     = "settings.write"
	PermissionUpstreamRead      = "upstream.read"
	PermissionUpstreamWrite     = "upstream.write"
	PermissionKeyRead           = "key.read"
	PermissionKeyWrite          = "key.write"
	PermissionLogRead           = "log.read"
	PermissionUserManage        = "user.manage"
	UpstreamScopeModeAll        = "all"
	UpstreamScopeModeSelected   = "selected"
)

type Upstream struct {
	ID                        string            `json:"id"`
	Name                      string            `json:"name"`
	APIEndpoint               string            `json:"api_endpoint"`
	NodeStatusAPIEndpoint     string            `json:"node_status_api_endpoint,omitempty"`
	NodeStatusRefreshInterval string            `json:"node_status_refresh_interval,omitempty"`
	Authorization             string            `json:"authorization"`
	RequestUserAgent          string            `json:"request_user_agent"`
	Host                      string            `json:"host"`
	Origin                    string            `json:"origin"`
	Referer                   string            `json:"referer"`
	CustomHeaders             map[string]string `json:"custom_headers,omitempty"`
	RefreshInterval           string            `json:"refresh_interval"`
	CacheStrategy             string            `json:"cache_strategy"`
	Enabled                   bool              `json:"enabled"`
	CreatedAt                 time.Time         `json:"created_at"`
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

type AdminUser struct {
	ID                string    `json:"id"`
	Username          string    `json:"username"`
	PasswordHash      string    `json:"password_hash"`
	Role              string    `json:"role"`
	CustomPermissions []string  `json:"custom_permissions,omitempty"`
	UpstreamScopeMode string    `json:"upstream_scope_mode,omitempty"`
	UpstreamScopeIDs  []string  `json:"upstream_scope_ids,omitempty"`
	Enabled           bool      `json:"enabled"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type AdminSession struct {
	UserID    string
	Username  string
	Role      string
	ExpiresAt time.Time
}

type persistedState struct {
	Upstreams []Upstream                  `json:"upstreams"`
	Keys      []AccessKey                 `json:"keys"`
	Users     []AdminUser                 `json:"users,omitempty"`
	Logs      []ClientUpdateLog           `json:"logs"`
	Config    GlobalConfig                `json:"config"`
	UASeen    map[string]map[string]int64 `json:"ua_seen,omitempty"`
	Version   int                         `json:"version"`
}

type State struct {
	mu              sync.RWMutex
	upstreams       map[string]Upstream
	keys            map[string]AccessKey
	keysByToken     map[string]string
	logs            []ClientUpdateLog
	caches          map[string]map[string]*CachedSubscription
	uaSeen          map[string]map[string]time.Time
	config          GlobalConfig
	adminUsers      map[string]AdminUser
	adminUserByName map[string]string
	adminSessions   map[string]AdminSession
	dataFile        string
}

func New(dataFile string, initialKeys []string, defaultRefreshInterval, adminUsername, adminPassword string) (*State, error) {
	s := &State{
		upstreams:       make(map[string]Upstream),
		keys:            make(map[string]AccessKey),
		keysByToken:     make(map[string]string),
		logs:            make([]ClientUpdateLog, 0),
		caches:          make(map[string]map[string]*CachedSubscription),
		uaSeen:          make(map[string]map[string]time.Time),
		adminUsers:      make(map[string]AdminUser),
		adminUserByName: make(map[string]string),
		adminSessions:   make(map[string]AdminSession),
		dataFile:        dataFile,
		config:          GlobalConfig{ActiveUADays: defaultActiveUADays, UANormalization: defaultUANormalizationConfig()},
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

	if err := s.ensureBootstrapAdminLocked(adminUsername, adminPassword); err != nil {
		return nil, err
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

func (s *State) ListAdminUsers() []AdminUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]AdminUser, 0, len(s.adminUsers))
	for _, user := range s.adminUsers {
		list = append(list, user)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	return list
}

func normalizeAdminRole(role string) string {
	switch strings.TrimSpace(role) {
	case AdminRoleSuperAdmin:
		return AdminRoleSuperAdmin
	case AdminRoleOperator:
		return AdminRoleOperator
	case AdminRoleViewer:
		return AdminRoleViewer
	default:
		return ""
	}
}

func permissionsByRole(role string) map[string]struct{} {
	switch role {
	case AdminRoleSuperAdmin:
		return map[string]struct{}{
			PermissionAdminRead:     {},
			PermissionAdminWrite:    {},
			PermissionSettingsWrite: {},
			PermissionUpstreamRead:  {},
			PermissionUpstreamWrite: {},
			PermissionKeyRead:       {},
			PermissionKeyWrite:      {},
			PermissionLogRead:       {},
			PermissionUserManage:    {},
		}
	case AdminRoleOperator:
		return map[string]struct{}{
			PermissionAdminRead:     {},
			PermissionAdminWrite:    {},
			PermissionSettingsWrite: {},
			PermissionUpstreamRead:  {},
			PermissionUpstreamWrite: {},
			PermissionKeyRead:       {},
			PermissionKeyWrite:      {},
			PermissionLogRead:       {},
		}
	case AdminRoleViewer:
		return map[string]struct{}{
			PermissionAdminRead:    {},
			PermissionUpstreamRead: {},
			PermissionKeyRead:      {},
			PermissionLogRead:      {},
		}
	default:
		return map[string]struct{}{}
	}
}

func normalizePermission(permission string) string {
	return strings.TrimSpace(permission)
}

func allPermissionSet() map[string]struct{} {
	return map[string]struct{}{
		PermissionAdminRead:     {},
		PermissionAdminWrite:    {},
		PermissionSettingsWrite: {},
		PermissionUpstreamRead:  {},
		PermissionUpstreamWrite: {},
		PermissionKeyRead:       {},
		PermissionKeyWrite:      {},
		PermissionLogRead:       {},
		PermissionUserManage:    {},
	}
}

func normalizeCustomPermissions(permissions []string) []string {
	if len(permissions) == 0 {
		return nil
	}
	known := allPermissionSet()
	seen := make(map[string]struct{}, len(permissions))
	result := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		normalized := normalizePermission(permission)
		if normalized == "" {
			continue
		}
		if _, ok := known[normalized]; !ok {
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
	sort.Strings(result)
	return result
}

func normalizeUpstreamScopeMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case UpstreamScopeModeAll:
		return UpstreamScopeModeAll
	case UpstreamScopeModeSelected:
		return UpstreamScopeModeSelected
	default:
		return ""
	}
}

func normalizeUpstreamScopeIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ids))
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		normalized := strings.TrimSpace(id)
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
	sort.Strings(result)
	return result
}

func (s *State) normalizeAndValidateScopeLocked(mode string, ids []string) (string, []string, error) {
	normalizedMode := normalizeUpstreamScopeMode(mode)
	if normalizedMode == "" {
		normalizedMode = UpstreamScopeModeAll
	}
	if normalizedMode == UpstreamScopeModeAll {
		return UpstreamScopeModeAll, nil, nil
	}
	normalizedIDs := normalizeUpstreamScopeIDs(ids)
	if len(normalizedIDs) == 0 {
		return "", nil, errors.New("指定上游范围模式时，至少选择一个上游")
	}
	for _, upstreamID := range normalizedIDs {
		if _, ok := s.upstreams[upstreamID]; !ok {
			return "", nil, errors.New("用户上游范围包含不存在的上游")
		}
	}
	return UpstreamScopeModeSelected, normalizedIDs, nil
}

func effectivePermissionsByUser(role string, custom []string) map[string]struct{} {
	result := permissionsByRole(normalizeAdminRole(role))
	for _, permission := range normalizeCustomPermissions(custom) {
		result[permission] = struct{}{}
	}
	return result
}

func (s *State) HasPermission(userID, role, permission string) bool {
	normalizedPermission := normalizePermission(permission)
	if normalizedPermission == "" {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if user, ok := s.adminUsers[userID]; ok {
		permissions := effectivePermissionsByUser(user.Role, user.CustomPermissions)
		_, exists := permissions[normalizedPermission]
		return exists
	}
	permissions := permissionsByRole(normalizeAdminRole(role))
	_, exists := permissions[normalizedPermission]
	return exists
}

func (s *State) UserCanAccessUpstream(userID, upstreamID string) bool {
	normalizedUpstreamID := strings.TrimSpace(upstreamID)
	if normalizedUpstreamID == "" {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.adminUsers[userID]
	if !ok || !user.Enabled {
		return false
	}
	mode := normalizeUpstreamScopeMode(user.UpstreamScopeMode)
	if mode == "" || mode == UpstreamScopeModeAll {
		return true
	}
	for _, id := range user.UpstreamScopeIDs {
		if id == normalizedUpstreamID {
			return true
		}
	}
	return false
}

func (s *State) UserAllowedUpstreamIDs(userID string) map[string]struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.adminUsers[userID]
	if !ok || !user.Enabled {
		return map[string]struct{}{}
	}
	mode := normalizeUpstreamScopeMode(user.UpstreamScopeMode)
	if mode == "" || mode == UpstreamScopeModeAll {
		result := make(map[string]struct{}, len(s.upstreams))
		for id := range s.upstreams {
			result[id] = struct{}{}
		}
		return result
	}
	result := make(map[string]struct{}, len(user.UpstreamScopeIDs))
	for _, id := range user.UpstreamScopeIDs {
		if _, ok := s.upstreams[id]; ok {
			result[id] = struct{}{}
		}
	}
	return result
}

func sortedPermissionsFromSet(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	list := make([]string, 0, len(set))
	for permission := range set {
		list = append(list, permission)
	}
	sort.Strings(list)
	return list
}

func RolePresetPermissions(role string) []string {
	return sortedPermissionsFromSet(permissionsByRole(normalizeAdminRole(role)))
}

func AllPermissions() []string {
	return sortedPermissionsFromSet(allPermissionSet())
}

func (s *State) GetAdminUser(userID string) (AdminUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.adminUsers[strings.TrimSpace(userID)]
	return user, ok
}

func (s *State) EffectivePermissions(userID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.adminUsers[strings.TrimSpace(userID)]
	if !ok {
		return nil
	}
	return sortedPermissionsFromSet(effectivePermissionsByUser(user.Role, user.CustomPermissions))
}

func normalizeAdminUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func verifyPassword(passwordHash, password string) bool {
	if strings.TrimSpace(passwordHash) == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) == nil
}

func (s *State) ensureBootstrapAdminLocked(adminUsername, adminPassword string) error {
	if len(s.adminUsers) > 0 {
		return nil
	}
	username := normalizeAdminUsername(adminUsername)
	if username == "" {
		username = "admin"
	}
	if strings.TrimSpace(adminPassword) == "" {
		return errors.New("管理员密码不能为空")
	}
	passwordHash, err := hashPassword(adminPassword)
	if err != nil {
		return fmt.Errorf("初始化管理员密码失败: %w", err)
	}
	now := time.Now()
	user := AdminUser{
		ID:                uuid.New().String(),
		Username:          username,
		PasswordHash:      passwordHash,
		Role:              AdminRoleSuperAdmin,
		CustomPermissions: nil,
		UpstreamScopeMode: UpstreamScopeModeAll,
		UpstreamScopeIDs:  nil,
		Enabled:           true,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	s.adminUsers[user.ID] = user
	s.adminUserByName[user.Username] = user.ID
	return nil
}

func (s *State) AuthenticateAdminUser(username, password string) (AdminUser, error) {
	normalizedUsername := normalizeAdminUsername(username)
	if normalizedUsername == "" || strings.TrimSpace(password) == "" {
		return AdminUser{}, errors.New("用户名或密码错误")
	}

	s.mu.RLock()
	userID, ok := s.adminUserByName[normalizedUsername]
	if !ok {
		s.mu.RUnlock()
		return AdminUser{}, errors.New("用户名或密码错误")
	}
	user, exists := s.adminUsers[userID]
	s.mu.RUnlock()
	if !exists || !user.Enabled {
		return AdminUser{}, errors.New("用户已禁用")
	}
	if !verifyPassword(user.PasswordHash, password) {
		return AdminUser{}, errors.New("用户名或密码错误")
	}
	return user, nil
}

func (s *State) CreateAdminSession(userID string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)

	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.adminUsers[userID]
	if !ok || !user.Enabled {
		return "", errors.New("用户不存在或已禁用")
	}

	s.adminSessions[token] = AdminSession{
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	return token, nil
}

func (s *State) ValidateAdminSession(token string) (AdminSession, bool) {
	if token == "" {
		return AdminSession{}, false
	}

	s.mu.RLock()
	session, ok := s.adminSessions[token]
	s.mu.RUnlock()
	if !ok || time.Now().After(session.ExpiresAt) {
		if ok {
			s.mu.Lock()
			delete(s.adminSessions, token)
			s.mu.Unlock()
		}
		return AdminSession{}, false
	}

	s.mu.RLock()
	user, exists := s.adminUsers[session.UserID]
	s.mu.RUnlock()
	if !exists || !user.Enabled {
		s.mu.Lock()
		delete(s.adminSessions, token)
		s.mu.Unlock()
		return AdminSession{}, false
	}

	session.Username = user.Username
	session.Role = user.Role
	return session, true
}

func (s *State) DeleteAdminSession(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.adminSessions, token)
}

func (s *State) enabledSuperAdminCountLocked() int {
	count := 0
	for _, user := range s.adminUsers {
		if user.Enabled && user.Role == AdminRoleSuperAdmin {
			count++
		}
	}
	return count
}

func (s *State) AddAdminUser(username, password, role string, customPermissions []string, upstreamScopeMode string, upstreamScopeIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	username = normalizeAdminUsername(username)
	if username == "" {
		return errors.New("用户名不能为空")
	}
	if strings.TrimSpace(password) == "" {
		return errors.New("密码不能为空")
	}
	role = normalizeAdminRole(role)
	if role == "" {
		return errors.New("无效的角色")
	}
	normalizedPermissions := normalizeCustomPermissions(customPermissions)
	normalizedScopeMode, normalizedScopeIDs, err := s.normalizeAndValidateScopeLocked(upstreamScopeMode, upstreamScopeIDs)
	if err != nil {
		return err
	}
	if _, exists := s.adminUserByName[username]; exists {
		return errors.New("用户名已存在")
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("生成密码失败: %w", err)
	}
	now := time.Now()
	user := AdminUser{
		ID:                uuid.New().String(),
		Username:          username,
		PasswordHash:      passwordHash,
		Role:              role,
		CustomPermissions: normalizedPermissions,
		UpstreamScopeMode: normalizedScopeMode,
		UpstreamScopeIDs:  normalizedScopeIDs,
		Enabled:           true,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	s.adminUsers[user.ID] = user
	s.adminUserByName[user.Username] = user.ID
	return s.saveLocked()
}

func (s *State) UpdateAdminUser(userID, username, role string, enabled bool, customPermissions []string, upstreamScopeMode string, upstreamScopeIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.adminUsers[userID]
	if !ok {
		return errors.New("用户不存在")
	}

	normalizedUsername := normalizeAdminUsername(username)
	if normalizedUsername == "" {
		return errors.New("用户名不能为空")
	}
	if existingID, exists := s.adminUserByName[normalizedUsername]; exists && existingID != userID {
		return errors.New("用户名已存在")
	}

	normalizedRole := normalizeAdminRole(role)
	if normalizedRole == "" {
		return errors.New("无效的角色")
	}
	normalizedPermissions := normalizeCustomPermissions(customPermissions)
	normalizedScopeMode, normalizedScopeIDs, err := s.normalizeAndValidateScopeLocked(upstreamScopeMode, upstreamScopeIDs)
	if err != nil {
		return err
	}

	if user.Role == AdminRoleSuperAdmin && (!enabled || normalizedRole != AdminRoleSuperAdmin) {
		if s.enabledSuperAdminCountLocked() <= 1 {
			return errors.New("至少保留一个启用的超级管理员")
		}
	}

	delete(s.adminUserByName, user.Username)
	user.Username = normalizedUsername
	user.Role = normalizedRole
	user.CustomPermissions = normalizedPermissions
	user.UpstreamScopeMode = normalizedScopeMode
	user.UpstreamScopeIDs = normalizedScopeIDs
	user.Enabled = enabled
	user.UpdatedAt = time.Now()
	s.adminUsers[userID] = user
	s.adminUserByName[user.Username] = userID

	for token, session := range s.adminSessions {
		if session.UserID != userID {
			continue
		}
		if !enabled {
			delete(s.adminSessions, token)
			continue
		}
		session.Username = user.Username
		session.Role = user.Role
		s.adminSessions[token] = session
	}

	return s.saveLocked()
}

func (s *State) UpdateAdminUserPassword(userID, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.adminUsers[userID]
	if !ok {
		return errors.New("用户不存在")
	}
	if strings.TrimSpace(newPassword) == "" {
		return errors.New("密码不能为空")
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("更新密码失败: %w", err)
	}
	user.PasswordHash = hash
	user.UpdatedAt = time.Now()
	s.adminUsers[userID] = user

	for token, session := range s.adminSessions {
		if session.UserID == userID {
			delete(s.adminSessions, token)
		}
	}

	return s.saveLocked()
}

func (s *State) DeleteAdminUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.adminUsers[userID]
	if !ok {
		return errors.New("用户不存在")
	}
	if user.Role == AdminRoleSuperAdmin && user.Enabled && s.enabledSuperAdminCountLocked() <= 1 {
		return errors.New("至少保留一个启用的超级管理员")
	}

	delete(s.adminUsers, userID)
	delete(s.adminUserByName, user.Username)
	for token, session := range s.adminSessions {
		if session.UserID == userID {
			delete(s.adminSessions, token)
		}
	}

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

func (s *State) DeleteUACacheVariant(upstreamID, userAgent string) (bool, bool, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.TrimSpace(upstreamID) == "" {
		return false, false, "", errors.New("upstream不能为空")
	}
	if _, ok := s.upstreams[upstreamID]; !ok {
		return false, false, "", errors.New("上游不存在")
	}

	variantKey := s.normalizeUAVariantLocked(userAgent)
	if variantKey == cacheVariantDefault {
		return false, false, variantKey, errors.New("默认UA缓存不支持删除")
	}

	removedCache := false
	if bucket, ok := s.caches[upstreamID]; ok && bucket != nil {
		if _, exists := bucket[variantKey]; exists {
			delete(bucket, variantKey)
			removedCache = true
		}
	}

	removedPlan := false
	if seenMap, ok := s.uaSeen[upstreamID]; ok && seenMap != nil {
		if _, exists := seenMap[variantKey]; exists {
			delete(seenMap, variantKey)
			removedPlan = true
		}
	}

	if !removedCache && !removedPlan {
		return false, false, variantKey, nil
	}

	if err := s.saveLocked(); err != nil {
		return false, false, variantKey, err
	}
	return removedCache, removedPlan, variantKey, nil
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

func (s *State) ListLogsPaginatedByUpstreamScope(page, pageSize int, allowedUpstreamIDs map[string]struct{}) LogPage {
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

	filtered := make([]ClientUpdateLog, 0, len(s.logs))
	for i := len(s.logs) - 1; i >= 0; i-- {
		entry := s.logs[i]
		if _, ok := allowedUpstreamIDs[entry.UpstreamID]; !ok {
			continue
		}
		filtered = append(filtered, entry)
	}

	total := len(filtered)
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}

	startIdx := (page - 1) * pageSize
	if startIdx > total {
		startIdx = total
	}
	endIdx := startIdx + pageSize
	if endIdx > total {
		endIdx = total
	}

	result := make([]ClientUpdateLog, 0, endIdx-startIdx)
	for _, entry := range filtered[startIdx:endIdx] {
		result = append(result, entry)
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

func (s *State) ListLogsByUpstreamScope(limit int, allowedUpstreamIDs map[string]struct{}) []ClientUpdateLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]ClientUpdateLog, 0)
	for i := len(s.logs) - 1; i >= 0; i-- {
		entry := s.logs[i]
		if _, ok := allowedUpstreamIDs[entry.UpstreamID]; !ok {
			continue
		}
		result = append(result, entry)
		if limit > 0 && len(result) >= limit {
			break
		}
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
	if u.NodeStatusRefreshInterval == "" {
		u.NodeStatusRefreshInterval = "10m"
	}
	if u.RequestUserAgent == "" {
		u.RequestUserAgent = defaultUserAgent
	}
	u.RefreshInterval = normalizeInterval(u.RefreshInterval)
	u.NodeStatusRefreshInterval = normalizeInterval(u.NodeStatusRefreshInterval)
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
	if u.NodeStatusRefreshInterval == "" {
		u.NodeStatusRefreshInterval = "10m"
	}
	if u.RequestUserAgent == "" {
		u.RequestUserAgent = defaultUserAgent
	}
	u.RefreshInterval = normalizeInterval(u.RefreshInterval)
	u.NodeStatusRefreshInterval = normalizeInterval(u.NodeStatusRefreshInterval)
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
	for userID, user := range s.adminUsers {
		if normalizeUpstreamScopeMode(user.UpstreamScopeMode) != UpstreamScopeModeSelected {
			continue
		}
		nextScopeIDs := make([]string, 0, len(user.UpstreamScopeIDs))
		for _, upstreamID := range user.UpstreamScopeIDs {
			if upstreamID == id {
				continue
			}
			nextScopeIDs = append(nextScopeIDs, upstreamID)
		}
		if len(nextScopeIDs) == 0 {
			user.UpstreamScopeMode = UpstreamScopeModeAll
			user.UpstreamScopeIDs = nil
		} else {
			user.UpstreamScopeIDs = nextScopeIDs
		}
		s.adminUsers[userID] = user
	}
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

	for _, user := range persisted.Users {
		username := normalizeAdminUsername(user.Username)
		if user.ID == "" || username == "" {
			continue
		}
		user.Username = username
		user.Role = normalizeAdminRole(user.Role)
		if user.Role == "" {
			user.Role = AdminRoleViewer
		}
		user.CustomPermissions = normalizeCustomPermissions(user.CustomPermissions)
		normalizedMode, normalizedIDs, err := s.normalizeAndValidateScopeLocked(user.UpstreamScopeMode, user.UpstreamScopeIDs)
		if err != nil {
			user.UpstreamScopeMode = UpstreamScopeModeAll
			user.UpstreamScopeIDs = nil
		} else {
			user.UpstreamScopeMode = normalizedMode
			user.UpstreamScopeIDs = normalizedIDs
		}
		s.adminUsers[user.ID] = user
		s.adminUserByName[user.Username] = user.ID
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

	users := make([]AdminUser, 0, len(s.adminUsers))
	for _, user := range s.adminUsers {
		users = append(users, user)
	}

	persisted := persistedState{
		Upstreams: upstreams,
		Keys:      keys,
		Users:     users,
		Logs:      s.logs,
		Config:    s.config,
		Version:   4,
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
