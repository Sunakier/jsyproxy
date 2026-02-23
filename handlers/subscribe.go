package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"jsyproxy/config"
	"jsyproxy/middleware"
	staticfiles "jsyproxy/static"
	"jsyproxy/store"
	"jsyproxy/utils"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var passthroughHeaderWhitelist = map[string]struct{}{
	"subscription-userinfo":     {},
	"x-sub-info":                {},
	"profile-title":             {},
	"profile-web-page-url":      {},
	"support-url":               {},
	"profile-update-interval":   {},
	"content-disposition":       {},
	"content-type":              {},
	"content-transfer-encoding": {},
}

type SubscribeResponse struct {
	Data struct {
		ExpiredAt      int64 `json:"expired_at"`
		U              int64 `json:"u"`
		D              int64 `json:"d"`
		TransferEnable int64 `json:"transfer_enable"`
		Plan           struct {
			Name string `json:"name"`
		} `json:"plan"`
		SubscribeURL string `json:"subscribe_url"`
		ResetDay     int    `json:"reset_day"`
	} `json:"data"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type addUserRequest struct {
	Username          string   `json:"username"`
	Password          string   `json:"password"`
	Role              string   `json:"role"`
	CustomPermissions []string `json:"custom_permissions"`
	UpstreamScopeMode string   `json:"upstream_scope_mode"`
	UpstreamScopeIDs  []string `json:"upstream_scope_ids"`
}

type updateUserRequest struct {
	Username          string   `json:"username"`
	Role              string   `json:"role"`
	Enabled           bool     `json:"enabled"`
	CustomPermissions []string `json:"custom_permissions"`
	UpstreamScopeMode string   `json:"upstream_scope_mode"`
	UpstreamScopeIDs  []string `json:"upstream_scope_ids"`
}

type updateUserPasswordRequest struct {
	Password string `json:"password"`
}

type addKeyRequest struct {
	Key        string `json:"key"`
	Name       string `json:"name"`
	UpstreamID string `json:"upstream_id"`
}

type updateKeyRequest struct {
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	UpstreamID string `json:"upstream_id"`
}

type upstreamRequest struct {
	ID                        string            `json:"id"`
	Name                      string            `json:"name"`
	Type                      string            `json:"type"`
	ContentMode               string            `json:"content_mode"`
	SubscriptionFormat        string            `json:"subscription_format"`
	ClashConfig               store.ClashConfig `json:"clash_config"`
	MergeConfig               store.MergeConfig `json:"merge_config"`
	APIEndpoint               string            `json:"api_endpoint"`
	NodeStatusAPIEndpoint     string            `json:"node_status_api_endpoint"`
	NodeStatusRefreshInterval string            `json:"node_status_refresh_interval"`
	Authorization             string            `json:"authorization"`
	RequestUserAgent          string            `json:"request_user_agent"`
	Host                      string            `json:"host"`
	Origin                    string            `json:"origin"`
	Referer                   string            `json:"referer"`
	CustomHeaders             map[string]string `json:"custom_headers"`
	RefreshInterval           string            `json:"refresh_interval"`
	CacheStrategy             string            `json:"cache_strategy"`
	Enabled                   bool              `json:"enabled"`
}

type requestConversionOptions struct {
	TargetFormat       string
	ConfigURL          string
	Includes           []string
	Excludes           []string
	RenameRules        []store.MergeNameReplacement
	EnableEmoji        bool
	SortNodes          bool
	DedupeNodes        bool
	OutputNodeListOnly bool
}

type globalConfigRequest struct {
	LogRetentionDays int                         `json:"log_retention_days"`
	ActiveUADays     int                         `json:"active_ua_days"`
	UANormalization  store.UANormalizationConfig `json:"ua_normalization"`
}

type uaRulesImportRequest struct {
	Enabled            *bool                       `json:"enabled"`
	UnknownPassthrough *bool                       `json:"unknown_passthrough"`
	Rules              []store.UANormalizationRule `json:"rules"`
}

type globalConfigImportRequest struct {
	GlobalConfig     *globalConfigRequest         `json:"global_config,omitempty"`
	LogRetentionDays *int                         `json:"log_retention_days,omitempty"`
	ActiveUADays     *int                         `json:"active_ua_days,omitempty"`
	UANormalization  *store.UANormalizationConfig `json:"ua_normalization,omitempty"`
}

type SubscribeHandler struct {
	config            *config.Config
	httpClient        *utils.HTTPClient
	state             *store.State
	refreshMutex      sync.Map
	loginMu           sync.Mutex
	loginAttempts     map[string]loginAttempt
	nodeStatusMu      sync.RWMutex
	nodeStatusCache   map[string]nodeStatusCacheEntry
	nodeStatusRunning map[string]bool
}

type loginAttempt struct {
	failed       int
	blockedUntil time.Time
	lastFailedAt time.Time
}

type nodeStatusFetchResponse struct {
	Data []map[string]interface{} `json:"data"`
}

type nodeStatusCacheEntry struct {
	Nodes     []gin.H
	Total     int
	Online    int
	FetchedAt time.Time
	ExpiresAt time.Time
	LastError string
}

// refreshLockValue holds the wait group for contended refreshes
type refreshLockValue struct {
	wg       sync.WaitGroup
	doneChan chan struct{}
}

const (
	refreshContentionTimeout = 10 * time.Second
	nodeStatusCacheTTL       = 10 * time.Minute
	maxLoginFailures         = 5
	loginBlockDuration       = 5 * time.Minute
	loginFailureWindow       = 15 * time.Minute
)

func NewSubscribeHandler(cfg *config.Config) (*SubscribeHandler, error) {
	state, err := store.New(cfg.DataFile, cfg.BootstrapAccessKeys, cfg.DefaultRefreshInterval, cfg.AdminUsername, cfg.AdminPassword)
	if err != nil {
		return nil, err
	}
	return &SubscribeHandler{
		config:            cfg,
		httpClient:        utils.NewHTTPClient(),
		state:             state,
		loginAttempts:     make(map[string]loginAttempt),
		nodeStatusCache:   make(map[string]nodeStatusCacheEntry),
		nodeStatusRunning: make(map[string]bool),
	}, nil
}

func (h *SubscribeHandler) ValidateAdminSession(token string) (string, string, string, bool) {
	session, ok := h.state.ValidateAdminSession(token)
	if !ok {
		return "", "", "", false
	}
	return session.UserID, session.Username, session.Role, true
}

func (h *SubscribeHandler) HasPermission(userID, role, permission string) bool {
	return h.state.HasPermission(userID, role, permission)
}

func (h *SubscribeHandler) StartAutoRefresh() {
	upstreams := h.state.ListUpstreams()
	for _, u := range upstreams {
		if u.Enabled && u.CacheStrategy == store.CacheStrategyForce {
			go h.runUpstreamRefreshLoop(u.ID)
		}
	}
}

func (h *SubscribeHandler) FlushState() error {
	return h.state.Flush()
}

func (h *SubscribeHandler) runUpstreamRefreshLoop(upstreamID string) {
	if err := h.RefreshUpstreamCache(upstreamID, "startup", ""); err != nil {
		log.Printf("启动预热缓存失败 upstream=%s: %v", upstreamID, err)
	}
	if err := h.refreshActiveUAVariants(upstreamID, "startup-active"); err != nil {
		log.Printf("启动活跃UA缓存预热失败 upstream=%s: %v", upstreamID, err)
	}
	for {
		interval := h.state.GetUpstreamRefreshInterval(upstreamID)
		time.Sleep(interval)

		upstream, ok := h.state.GetUpstream(upstreamID)
		if !ok || !upstream.Enabled || upstream.CacheStrategy != store.CacheStrategyForce {
			log.Printf("停止上游刷新循环 upstream=%s (已删除或禁用或策略变更)", upstreamID)
			return
		}

		if err := h.RefreshUpstreamCache(upstreamID, "timer", ""); err != nil {
			log.Printf("定时刷新缓存失败 upstream=%s: %v", upstreamID, err)
		}
		if err := h.refreshActiveUAVariants(upstreamID, "timer-active"); err != nil {
			log.Printf("定时活跃UA缓存刷新失败 upstream=%s: %v", upstreamID, err)
		}
	}
}

func (h *SubscribeHandler) refreshActiveUAVariants(upstreamID, reason string) error {
	upstream, ok := h.state.GetUpstream(upstreamID)
	if !ok || !upstream.Enabled || upstream.CacheStrategy != store.CacheStrategyForce {
		return nil
	}
	variants := h.state.ListActiveUAVariants(upstreamID)
	var lastErr error
	for _, ua := range variants {
		if strings.TrimSpace(ua) == "" {
			continue
		}
		if err := h.RefreshUpstreamCache(upstreamID, reason, ua); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (h *SubscribeHandler) GetSubscribe(c *gin.Context) {
	accessKeyToken := strings.TrimSpace(c.Query("token"))
	if accessKeyToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "缺少token参数"})
		return
	}

	keyInfo, ok := h.state.GetKeyByToken(accessKeyToken)
	if !ok || !keyInfo.Enabled {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的token"})
		return
	}

	upstream, ok := h.state.GetUpstream(keyInfo.UpstreamID)
	if !ok || !upstream.Enabled {
		c.JSON(http.StatusBadGateway, gin.H{"error": "上游服务不可用"})
		return
	}

	clientUA := c.GetHeader("User-Agent")
	clientIP := c.ClientIP()
	h.state.MarkUASeen(keyInfo.UpstreamID, clientUA)
	clientUA = strings.TrimSpace(clientUA)
	uaDetails := h.state.ResolveUAMatchDetails(clientUA)

	cacheVariantUA := uaDetails.CacheBucket
	cache, cacheHit := h.state.GetCache(keyInfo.UpstreamID, cacheVariantUA)
	variantMiss := cacheVariantUA != "" && !cacheHit
	if !cacheHit && cacheVariantUA != "" {
		if fallbackCache, fallbackHit := h.state.GetCache(keyInfo.UpstreamID, ""); fallbackHit {
			cache = fallbackCache
			cacheHit = true
			cacheVariantUA = ""
		}
	}

	needRefresh := false
	if !cacheHit || variantMiss {
		needRefresh = true
	} else if upstream.CacheStrategy == store.CacheStrategyLazy && h.state.IsCacheExpired(keyInfo.UpstreamID, cacheVariantUA) {
		needRefresh = true
	}

	if needRefresh {
		refreshUA := cacheVariantUA
		if variantMiss {
			refreshUA = clientUA
		} else if !cacheHit {
			refreshUA = ""
		}
		if err := h.RefreshUpstreamCache(keyInfo.UpstreamID, "request", refreshUA); err != nil {
			h.appendClientLog(keyInfo.ID, keyInfo.Key, keyInfo.Name, keyInfo.UpstreamID, clientIP, clientUA, uaDetails, false, "failed", err.Error())
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		cache, cacheHit = h.state.GetCache(keyInfo.UpstreamID, clientUA)
		if !cacheHit && clientUA != "" {
			cache, cacheHit = h.state.GetCache(keyInfo.UpstreamID, "")
		}
		if !cacheHit {
			h.appendClientLog(keyInfo.ID, keyInfo.Key, keyInfo.Name, keyInfo.UpstreamID, clientIP, clientUA, uaDetails, false, "failed", "缓存刷新后为空")
			c.JSON(http.StatusBadGateway, gin.H{"error": "订阅内容不可用"})
			return
		}
	}

	conversionOptions, hasConversionOptions, conversionErr := parseRequestConversionOptions(c)
	if conversionErr != nil {
		h.appendClientLog(keyInfo.ID, keyInfo.Key, keyInfo.Name, keyInfo.UpstreamID, clientIP, clientUA, uaDetails, cacheHit, "failed", conversionErr.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": conversionErr.Error()})
		return
	}
	if hasConversionOptions {
		convertedBody, convertedHeaders, err := h.applyRequestConversion(cache, upstream, conversionOptions)
		if err != nil {
			h.appendClientLog(keyInfo.ID, keyInfo.Key, keyInfo.Name, keyInfo.UpstreamID, clientIP, clientUA, uaDetails, cacheHit, "failed", err.Error())
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		cache = &store.CachedSubscription{
			Body:       convertedBody,
			Headers:    convertedHeaders,
			StatusCode: cache.StatusCode,
		}
	}

	copyHeaders(cache.Headers, c.Writer.Header())
	c.Status(cache.StatusCode)
	if _, err := c.Writer.Write(cache.Body); err != nil {
		h.appendClientLog(keyInfo.ID, keyInfo.Key, keyInfo.Name, keyInfo.UpstreamID, clientIP, clientUA, uaDetails, cacheHit, "failed", "写响应失败")
		return
	}
	h.appendClientLog(keyInfo.ID, keyInfo.Key, keyInfo.Name, keyInfo.UpstreamID, clientIP, clientUA, uaDetails, cacheHit, "success", "")
}

func parseRequestConversionOptions(c *gin.Context) (requestConversionOptions, bool, error) {
	opts := requestConversionOptions{}
	if raw := strings.TrimSpace(c.Query("target")); raw != "" {
		format, ok := normalizeRequestTargetFormat(raw)
		if !ok {
			return requestConversionOptions{}, false, errors.New("不支持的target参数")
		}
		opts.TargetFormat = format
	}
	if raw := strings.TrimSpace(c.Query("config")); raw != "" {
		opts.ConfigURL = raw
	}
	if raw := strings.TrimSpace(c.Query("include")); raw != "" {
		opts.Includes = splitFilterTerms(raw)
	}
	excludeRaw := strings.TrimSpace(c.Query("exclude"))
	if excludeRaw == "" {
		excludeRaw = strings.TrimSpace(c.Query("wxclude"))
	}
	if excludeRaw != "" {
		opts.Excludes = splitFilterTerms(excludeRaw)
	}
	if raw := strings.TrimSpace(c.Query("rename")); raw != "" {
		opts.RenameRules = parseQueryRenameRules(raw)
	}
	if parsed, ok := parseBoolQuery(c.Query("emoji")); ok {
		opts.EnableEmoji = parsed
	}
	if parsed, ok := parseBoolQuery(c.Query("sort")); ok {
		opts.SortNodes = parsed
	}
	if parsed, ok := parseBoolQuery(c.Query("dedupe")); ok {
		opts.DedupeNodes = parsed
	}
	if parsed, ok := parseBoolQuery(c.Query("list")); ok {
		opts.OutputNodeListOnly = parsed
	}
	hasAny := opts.TargetFormat != "" || opts.ConfigURL != "" || len(opts.Includes) > 0 || len(opts.Excludes) > 0 || len(opts.RenameRules) > 0 || opts.EnableEmoji || opts.SortNodes || opts.DedupeNodes || opts.OutputNodeListOnly
	return opts, hasAny, nil
}

func normalizeRequestTargetFormat(raw string) (string, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	switch trimmed {
	case store.SubscriptionFormatV2Ray, "mixed":
		return store.SubscriptionFormatV2Ray, true
	case store.SubscriptionFormatClash:
		return store.SubscriptionFormatClash, true
	case "clash-meta", "clashmeta", "clash.meta", store.SubscriptionFormatClashMeta, "meta":
		return store.SubscriptionFormatClashMeta, true
	case store.SubscriptionFormatMihomo:
		return store.SubscriptionFormatMihomo, true
	case store.SubscriptionFormatStash:
		return store.SubscriptionFormatStash, true
	case store.SubscriptionFormatSurge:
		return store.SubscriptionFormatSurge, true
	case "sing-box", store.SubscriptionFormatSingBox:
		return store.SubscriptionFormatSingBox, true
	default:
		return "", false
	}
}

func splitFilterTerms(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	parts := []string{trimmed}
	if strings.Contains(trimmed, "``") {
		parts = strings.Split(trimmed, "``")
	} else if strings.Contains(trimmed, "\n") {
		parts = strings.Split(trimmed, "\n")
	}
	result := make([]string, 0, len(parts))
	for _, item := range parts {
		token := strings.TrimSpace(item)
		if token == "" {
			continue
		}
		result = append(result, token)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func parseQueryRenameRules(raw string) []store.MergeNameReplacement {
	items := strings.Split(raw, "``")
	result := make([]store.MergeNameReplacement, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		parts := strings.SplitN(trimmed, "@", 2)
		if len(parts) != 2 {
			continue
		}
		from := strings.TrimSpace(parts[0])
		if from == "" {
			continue
		}
		result = append(result, store.MergeNameReplacement{From: from, To: strings.TrimSpace(parts[1])})
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func parseBoolQuery(raw string) (bool, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return false, false
	}
	switch trimmed {
	case "1", "true", "on", "yes", "y":
		return true, true
	case "0", "false", "off", "no", "n":
		return false, true
	default:
		return false, false
	}
}

func cloneHeaderMap(src map[string][]string) map[string][]string {
	if src == nil {
		return map[string][]string{}
	}
	result := make(map[string][]string, len(src))
	for key, values := range src {
		result[key] = append([]string(nil), values...)
	}
	return result
}

func (h *SubscribeHandler) applyRequestConversion(cache *store.CachedSubscription, upstream store.Upstream, opts requestConversionOptions) ([]byte, map[string][]string, error) {
	nodes, err := ParseSubscriptionNodes(cache.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("按请求参数转换失败: %w", err)
	}
	if len(opts.RenameRules) > 0 {
		nodes = ApplyNameReplacements(nodes, opts.RenameRules)
	}
	if opts.EnableEmoji {
		nodes = ApplyProtocolEmoji(nodes)
	}
	nodes = FilterNodes(nodes, opts.Includes, opts.Excludes, nil)
	if opts.DedupeNodes {
		nodes = DedupeMergedNodes(nodes)
	}
	if opts.SortNodes {
		nodes = SortMergedNodesByName(nodes)
	}
	if len(nodes) == 0 {
		return nil, nil, errors.New("过滤后没有可用节点")
	}

	format := upstream.SubscriptionFormat
	if format == "" {
		format = store.SubscriptionFormatV2Ray
	}
	if opts.TargetFormat != "" {
		format = opts.TargetFormat
	}

	headers := cloneHeaderMap(cache.Headers)
	if opts.OutputNodeListOnly {
		plainLines, err := renderPlainNodeList(nodes)
		if err != nil {
			return nil, nil, err
		}
		setHeaderValues(headers, "Content-Type", []string{"text/plain; charset=utf-8"})
		deleteHeader(headers, "Content-Transfer-Encoding")
		return plainLines, headers, nil
	}

	if format == store.SubscriptionFormatClash || format == store.SubscriptionFormatClashMeta || format == store.SubscriptionFormatMihomo || format == store.SubscriptionFormatStash {
		additionalRules, err := h.loadRulesFromConfigURL(opts.ConfigURL)
		if err != nil {
			return nil, nil, err
		}
		body, err := RenderClashSubscription(nodes, cache.Body, upstream.ClashConfig, ClashRenderOptions{AdditionalRules: additionalRules})
		if err != nil {
			return nil, nil, err
		}
		setHeaderValues(headers, "Content-Type", []string{"text/yaml; charset=utf-8"})
		deleteHeader(headers, "Content-Transfer-Encoding")
		return body, headers, nil
	}

	if format == store.SubscriptionFormatSurge {
		body, err := RenderSurgeSubscription(nodes)
		if err != nil {
			return nil, nil, err
		}
		setHeaderValues(headers, "Content-Type", []string{"text/plain; charset=utf-8"})
		deleteHeader(headers, "Content-Transfer-Encoding")
		return body, headers, nil
	}

	if format == store.SubscriptionFormatSingBox {
		body, err := RenderSingBoxSubscription(nodes, cache.Body)
		if err != nil {
			return nil, nil, err
		}
		setHeaderValues(headers, "Content-Type", []string{"application/json; charset=utf-8"})
		deleteHeader(headers, "Content-Transfer-Encoding")
		return body, headers, nil
	}

	body, err := RenderStandardV2RaySubscription(nodes)
	if err != nil {
		return nil, nil, err
	}
	setHeaderValues(headers, "Content-Type", []string{"text/plain; charset=utf-8"})
	setHeaderValues(headers, "Content-Transfer-Encoding", []string{"base64"})
	return body, headers, nil
}

func renderPlainNodeList(nodes []MergedNode) ([]byte, error) {
	lines := make([]string, 0, len(nodes))
	for _, node := range nodes {
		line, err := node.render(node.Name)
		if err != nil {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lines = append(lines, trimmed)
	}
	if len(lines) == 0 {
		return nil, errors.New("没有可输出节点")
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func (h *SubscribeHandler) loadRulesFromConfigURL(configURL string) ([]string, error) {
	trimmed := strings.TrimSpace(configURL)
	if trimmed == "" {
		return nil, nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, errors.New("config参数不是合法URL")
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return nil, errors.New("config仅支持http/https链接")
	}
	rules, err := h.fetchRulesFromConfig(parsed.String(), 0)
	if err != nil {
		return nil, err
	}
	return dedupeRuleStrings(rules), nil
}

func (h *SubscribeHandler) fetchRulesFromConfig(configURL string, depth int) ([]string, error) {
	if depth > 2 {
		return nil, errors.New("config规则嵌套层级过深")
	}
	resp, err := h.httpClient.MakeRequest(http.MethodGet, configURL, map[string]string{})
	if err != nil {
		return nil, fmt.Errorf("拉取config失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("拉取config失败: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取config失败: %w", err)
	}
	return h.parseRulesFromConfigBody(configURL, body, depth)
}

func (h *SubscribeHandler) parseRulesFromConfigBody(baseURL string, body []byte, depth int) ([]string, error) {
	raw := string(body)
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	if rules := parseRulesFromProviderYAML(trimmed); len(rules) > 0 {
		return rules, nil
	}
	if strings.Contains(trimmed, "[custom]") || strings.Contains(trimmed, "ruleset=") {
		return h.parseRulesFromACLINI(baseURL, trimmed)
	}
	return parseRulesFromList(trimmed, "PROXY"), nil
}

func parseRulesFromProviderYAML(raw string) []string {
	root := parseYAMLMap([]byte(raw))
	if root == nil {
		return nil
	}
	payload, ok := root["payload"].([]interface{})
	if !ok {
		return nil
	}
	rules := make([]string, 0, len(payload))
	for _, item := range payload {
		rule := appendPolicyToRule(asString(item), "PROXY")
		if rule == "" {
			continue
		}
		rules = append(rules, rule)
	}
	return rules
}

func (h *SubscribeHandler) parseRulesFromACLINI(baseURL, raw string) ([]string, error) {
	lines := strings.Split(raw, "\n")
	rules := make([]string, 0, len(lines)*2)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(trimmed), "ruleset=") {
			continue
		}
		value := strings.TrimSpace(trimmed[len("ruleset="):])
		if value == "" {
			continue
		}
		parts := strings.SplitN(value, ",", 2)
		if len(parts) != 2 {
			continue
		}
		policy := strings.TrimSpace(parts[0])
		source := strings.TrimSpace(parts[1])
		if policy == "" || source == "" {
			continue
		}
		if strings.HasPrefix(source, "[]") {
			rule := appendPolicyToRule(strings.TrimSpace(source[2:]), policy)
			if rule != "" {
				rules = append(rules, rule)
			}
			continue
		}
		sourceURL := source
		if !strings.HasPrefix(strings.ToLower(sourceURL), "http://") && !strings.HasPrefix(strings.ToLower(sourceURL), "https://") {
			if base, err := url.Parse(baseURL); err == nil {
				if ref, err := url.Parse(sourceURL); err == nil {
					sourceURL = base.ResolveReference(ref).String()
				}
			}
		}
		resp, err := h.httpClient.MakeRequest(http.MethodGet, sourceURL, map[string]string{})
		if err != nil {
			continue
		}
		content, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		rules = append(rules, parseRulesFromList(string(content), policy)...)
	}
	return rules, nil
}

func parseRulesFromList(raw string, policy string) []string {
	lines := strings.Split(raw, "\n")
	rules := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		rule := appendPolicyToRule(trimmed, policy)
		if rule == "" {
			continue
		}
		rules = append(rules, rule)
	}
	return rules
}

func appendPolicyToRule(rule string, policy string) string {
	trimmed := strings.TrimSpace(rule)
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, ",")
	if len(parts) == 1 {
		return ""
	}
	normalizedPolicy := strings.TrimSpace(policy)
	if normalizedPolicy == "" {
		normalizedPolicy = "PROXY"
	}
	if len(parts) == 2 {
		return trimmed + "," + normalizedPolicy
	}
	last := strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))
	if last == "no-resolve" {
		if len(parts) == 3 {
			return strings.Join([]string{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), normalizedPolicy, strings.TrimSpace(parts[2])}, ",")
		}
		return trimmed
	}
	return trimmed
}

func dedupeRuleStrings(rules []string) []string {
	seen := make(map[string]struct{}, len(rules))
	result := make([]string, 0, len(rules))
	for _, rule := range rules {
		trimmed := strings.TrimSpace(rule)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func (h *SubscribeHandler) RefreshUpstreamCache(upstreamID, reason, downstreamUA string) error {
	variantKey := h.state.NormalizeUAVariant(downstreamUA)
	lockKey := makeRefreshLockKey(upstreamID, variantKey)

	// Try to acquire lock or wait for in-flight refresh
	lockVal := h.acquireRefreshLock(lockKey)
	if lockVal == nil {
		// Another goroutine is refreshing - wait for it to complete
		select {
		case <-time.After(refreshContentionTimeout):
			return errors.New("等待上游刷新超时，请稍后重试")
		case <-h.waitForRefresh(lockKey):
			// In-flight refresh completed - check if cache now exists
			if cache, hit := h.state.GetCache(upstreamID, variantKey); hit && cache != nil {
				return nil
			}
			return errors.New("上游刷新未完成，缓存不可用")
		}
	}
	defer h.releaseRefreshLock(lockKey, lockVal)

	upstream, ok := h.state.GetUpstream(upstreamID)
	if !ok {
		return errors.New("上游不存在")
	}
	if strings.TrimSpace(upstream.APIEndpoint) == "" {
		if upstream.Type != store.UpstreamTypeMerge {
			return errors.New("请先配置API端点地址")
		}
	}

	if upstream.Type == store.UpstreamTypeMerge {
		return h.refreshMergeUpstreamCache(upstream, reason, downstreamUA)
	}
	return h.refreshSingleUpstreamCache(upstream, reason, downstreamUA)
}

func (h *SubscribeHandler) refreshSingleUpstreamCache(upstream store.Upstream, reason, downstreamUA string) error {
	fetched, err := h.fetchSingleUpstreamContent(upstream, downstreamUA)
	if err != nil {
		return err
	}
	body := fetched.Body
	headers := fetched.Headers
	if upstream.ContentMode == store.ContentModeModify {
		headers = filterAllowedPassthroughHeaders(fetched.Headers)
		ensureTrafficMetadataHeaders(headers, fetched.TrafficStatus)
		nodes, err := ParseSubscriptionNodes(fetched.Body)
		if err != nil {
			return fmt.Errorf("解析订阅内容失败: %w", err)
		}
		nodes = ApplyNameReplacements(nodes, upstream.MergeConfig.NameReplacements)
		nodes = FilterNodes(nodes, upstream.MergeConfig.IncludeNameContains, upstream.MergeConfig.ExcludeNameContains, upstream.MergeConfig.Rules)
		if len(nodes) == 0 {
			return errors.New("修改内容后没有可用节点")
		}
		switch upstream.SubscriptionFormat {
		case store.SubscriptionFormatClash, store.SubscriptionFormatClashMeta, store.SubscriptionFormatMihomo, store.SubscriptionFormatStash:
			rendered, err := RenderClashSubscription(nodes, fetched.Body, upstream.ClashConfig)
			if err != nil {
				return err
			}
			body = rendered
			setHeaderValues(headers, "Content-Type", []string{"text/yaml; charset=utf-8"})
			deleteHeader(headers, "Content-Transfer-Encoding")
		case store.SubscriptionFormatSurge:
			rendered, err := RenderSurgeSubscription(nodes)
			if err != nil {
				return err
			}
			body = rendered
			setHeaderValues(headers, "Content-Type", []string{"text/plain; charset=utf-8"})
			deleteHeader(headers, "Content-Transfer-Encoding")
		case store.SubscriptionFormatSingBox:
			rendered, err := RenderSingBoxSubscription(nodes, fetched.Body)
			if err != nil {
				return err
			}
			body = rendered
			setHeaderValues(headers, "Content-Type", []string{"application/json; charset=utf-8"})
			deleteHeader(headers, "Content-Transfer-Encoding")
		default:
			rendered, err := RenderStandardV2RaySubscription(nodes)
			if err != nil {
				return err
			}
			body = rendered
			setHeaderValues(headers, "Content-Type", []string{"text/plain; charset=utf-8"})
			setHeaderValues(headers, "Content-Transfer-Encoding", []string{"base64"})
		}
	}
	cacheVariantUA := strings.TrimSpace(downstreamUA)
	h.state.SetCache(upstream.ID, cacheVariantUA, &store.CachedSubscription{
		Body:          body,
		Headers:       headers,
		StatusCode:    fetched.StatusCode,
		UpdatedAt:     time.Now(),
		SourceURL:     fetched.SourceURL,
		TrafficStatus: fetched.TrafficStatus,
	})
	log.Printf("订阅缓存刷新成功 upstream=%s reason=%s source=%s bytes=%d", upstream.ID, reason, fetched.SourceURL, len(fetched.Body))
	return nil
}

func (h *SubscribeHandler) refreshMergeUpstreamCache(upstream store.Upstream, reason, downstreamUA string) error {
	nodes := make([]MergedNode, 0)
	passthroughHeaders := make(map[string][]string)
	mergedTraffic := store.TrafficStatus{}
	for _, source := range upstream.MergeConfig.Sources {
		if source.Enabled != nil && !*source.Enabled {
			continue
		}
		sourceUpstream, ok := h.state.GetUpstream(source.UpstreamID)
		if !ok {
			continue
		}
		if !sourceUpstream.Enabled {
			continue
		}
		if sourceUpstream.Type == store.UpstreamTypeMerge {
			continue
		}
		fetched, err := h.fetchSingleUpstreamContent(sourceUpstream, downstreamUA)
		if err != nil {
			log.Printf("M类上游来源拉取失败 merge=%s source=%s: %v", upstream.ID, source.UpstreamID, err)
			continue
		}
		mergeAllowedPassthroughHeadersFromMap(passthroughHeaders, fetched.Headers)
		mergeTrafficStatus(&mergedTraffic, fetched.TrafficStatus)
		parsed, err := ParseSubscriptionNodes(fetched.Body)
		if err != nil {
			log.Printf("M类上游来源解析失败 merge=%s source=%s: %v", upstream.ID, source.UpstreamID, err)
			continue
		}
		for _, node := range parsed {
			if source.Prefix != "" {
				node.Name = source.Prefix + node.Name
			}
			nodes = append(nodes, node)
		}
	}

	nodes = ApplyNameReplacements(nodes, upstream.MergeConfig.NameReplacements)
	nodes = FilterNodes(nodes, upstream.MergeConfig.IncludeNameContains, upstream.MergeConfig.ExcludeNameContains, upstream.MergeConfig.Rules)
	if len(nodes) == 0 {
		return errors.New("M类上游合并后没有可用节点")
	}

	var body []byte
	var err error
	headers := filterAllowedPassthroughHeaders(passthroughHeaders)
	ensureTrafficMetadataHeaders(headers, mergedTraffic)
	if upstream.SubscriptionFormat == store.SubscriptionFormatClash || upstream.SubscriptionFormat == store.SubscriptionFormatClashMeta || upstream.SubscriptionFormat == store.SubscriptionFormatMihomo || upstream.SubscriptionFormat == store.SubscriptionFormatStash {
		body, err = RenderClashSubscription(nodes, nil, upstream.ClashConfig)
		if err != nil {
			return err
		}
		setHeaderValues(headers, "Content-Type", []string{"text/yaml; charset=utf-8"})
		deleteHeader(headers, "Content-Transfer-Encoding")
	} else if upstream.SubscriptionFormat == store.SubscriptionFormatSurge {
		body, err = RenderSurgeSubscription(nodes)
		if err != nil {
			return err
		}
		setHeaderValues(headers, "Content-Type", []string{"text/plain; charset=utf-8"})
		deleteHeader(headers, "Content-Transfer-Encoding")
	} else if upstream.SubscriptionFormat == store.SubscriptionFormatSingBox {
		body, err = RenderSingBoxSubscription(nodes, nil)
		if err != nil {
			return err
		}
		setHeaderValues(headers, "Content-Type", []string{"application/json; charset=utf-8"})
		deleteHeader(headers, "Content-Transfer-Encoding")
	} else {
		body, err = RenderStandardV2RaySubscription(nodes)
		if err != nil {
			return err
		}
		setHeaderValues(headers, "Content-Type", []string{"text/plain; charset=utf-8"})
		setHeaderValues(headers, "Content-Transfer-Encoding", []string{"base64"})
	}
	h.state.SetCache(upstream.ID, downstreamUA, &store.CachedSubscription{
		Body:          body,
		Headers:       headers,
		StatusCode:    http.StatusOK,
		UpdatedAt:     time.Now(),
		SourceURL:     "merge://" + upstream.ID,
		TrafficStatus: mergedTraffic,
	})
	log.Printf("M类订阅缓存刷新成功 upstream=%s reason=%s nodes=%d bytes=%d", upstream.ID, reason, len(nodes), len(body))
	return nil
}

type fetchedSubscription struct {
	Body          []byte
	Headers       map[string][]string
	StatusCode    int
	SourceURL     string
	TrafficStatus store.TrafficStatus
}

func (h *SubscribeHandler) fetchSingleUpstreamContent(upstream store.Upstream, downstreamUA string) (*fetchedSubscription, error) {
	if strings.TrimSpace(upstream.APIEndpoint) == "" {
		return nil, errors.New("请先配置API端点地址")
	}

	headers := buildUpstreamRequestHeaders(upstream)

	resp, err := h.httpClient.MakeRequest(http.MethodGet, upstream.APIEndpoint, headers)
	if err != nil {
		return nil, fmt.Errorf("请求上游API失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("上游API返回状态码: %d", resp.StatusCode)
	}

	var subscribeResp SubscribeResponse
	if err := utils.ParseJSONResponse(resp, &subscribeResp); err != nil {
		return nil, fmt.Errorf("解析上游响应失败: %w", err)
	}
	if subscribeResp.Data.SubscribeURL == "" {
		return nil, errors.New("上游响应缺少subscribe_url")
	}

	fetchUA := strings.TrimSpace(downstreamUA)
	if fetchUA == "" {
		fetchUA = upstream.RequestUserAgent
	}
	contentHeaders := map[string]string{}
	if fetchUA != "" {
		contentHeaders["User-Agent"] = fetchUA
	}
	contentResp, err := h.httpClient.MakeRequest(http.MethodGet, subscribeResp.Data.SubscribeURL, contentHeaders)
	if err != nil {
		return nil, fmt.Errorf("请求订阅链接失败: %w", err)
	}
	defer contentResp.Body.Close()
	if contentResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("订阅内容返回状态码: %d", contentResp.StatusCode)
	}

	body, err := io.ReadAll(contentResp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取订阅内容失败: %w", err)
	}

	headersCopy := make(map[string][]string)
	for k, values := range contentResp.Header {
		headersCopy[k] = append([]string(nil), values...)
	}
	mergeAllowedPassthroughHeaders(headersCopy, resp.Header)
	trafficStatus := store.TrafficStatus{
		ExpiredAt:      subscribeResp.Data.ExpiredAt,
		UsedUpload:     subscribeResp.Data.U,
		UsedDownload:   subscribeResp.Data.D,
		TransferEnable: subscribeResp.Data.TransferEnable,
		PlanName:       subscribeResp.Data.Plan.Name,
		ResetDay:       subscribeResp.Data.ResetDay,
	}
	ensureTrafficMetadataHeaders(headersCopy, trafficStatus)
	return &fetchedSubscription{
		Body:          body,
		Headers:       headersCopy,
		StatusCode:    contentResp.StatusCode,
		SourceURL:     subscribeResp.Data.SubscribeURL,
		TrafficStatus: trafficStatus,
	}, nil
}

func makeRefreshLockKey(upstreamID, userAgent string) string {
	ua := strings.TrimSpace(userAgent)
	if ua == "" {
		ua = "__default__"
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(ua))
	return fmt.Sprintf("refresh_%s_%x", upstreamID, h.Sum64())
}

// acquireRefreshLock attempts to acquire the refresh lock for the given key.
// Returns nil if another goroutine is already refreshing (caller should wait).
// Returns the lock value if this goroutine acquired the lock (caller should refresh).
func (h *SubscribeHandler) acquireRefreshLock(lockKey string) *refreshLockValue {
	lockVal, loaded := h.refreshMutex.LoadOrStore(lockKey, &refreshLockValue{
		doneChan: make(chan struct{}),
	})
	if loaded {
		return nil
	}
	// We acquired the lock - initialize the wait group for others to wait on
	lockVal.(*refreshLockValue).wg.Add(1)
	return lockVal.(*refreshLockValue)
}

// waitForRefresh returns a channel that signals when the in-flight refresh completes.
func (h *SubscribeHandler) waitForRefresh(lockKey string) <-chan struct{} {
	lockVal, ok := h.refreshMutex.Load(lockKey)
	if !ok {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return lockVal.(*refreshLockValue).doneChan
}

// releaseRefreshLock releases the refresh lock and signals waiting goroutines.
func (h *SubscribeHandler) releaseRefreshLock(lockKey string, lockVal *refreshLockValue) {
	lockVal.wg.Done()
	close(lockVal.doneChan)
	h.refreshMutex.Delete(lockKey)
}

func (h *SubscribeHandler) AdminPage(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", staticfiles.AdminHTML)
}

func (h *SubscribeHandler) AdminLogin(c *gin.Context) {
	clientIP := c.ClientIP()
	if allowed, retryAfter := h.allowAdminLogin(clientIP); !allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": fmt.Sprintf("登录失败次数过多，请在 %d 秒后重试", retryAfter)})
		return
	}

	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = "admin"
	}
	user, err := h.state.AuthenticateAdminUser(username, req.Password)
	if err != nil {
		h.recordAdminLoginFailure(clientIP)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}
	token, err := h.state.CreateAdminSession(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
		return
	}
	h.recordAdminLoginSuccess(clientIP)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("admin_session", token, 86400, "/admin", "", h.shouldUseSecureCookie(c), true)
	effectivePermissions := h.state.EffectivePermissions(user.ID)
	scopeMode := user.UpstreamScopeMode
	if strings.TrimSpace(scopeMode) == "" {
		scopeMode = store.UpstreamScopeModeAll
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "user": gin.H{
		"id":                    user.ID,
		"username":              user.Username,
		"role":                  user.Role,
		"custom_permissions":    user.CustomPermissions,
		"effective_permissions": effectivePermissions,
		"upstream_scope_mode":   scopeMode,
		"upstream_scope_ids":    user.UpstreamScopeIDs,
	}})
}

func (h *SubscribeHandler) AdminLogout(c *gin.Context) {
	if token, err := c.Cookie("admin_session"); err == nil {
		h.state.DeleteAdminSession(token)
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("admin_session", "", -1, "/admin", "", h.shouldUseSecureCookie(c), true)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminStatus(c *gin.Context) {
	currentUser := h.currentAdminUser(c)
	upstreams := h.filterUpstreamsByCurrentUser(c, h.state.ListUpstreams())
	allowedUpstreamIDs := h.currentAllowedUpstreamIDs(c)
	filteredKeys := h.filterKeysByCurrentUser(c, h.state.ListKeys())
	filteredLogs := h.state.ListLogsByUpstreamScope(0, allowedUpstreamIDs)
	upstreamStatuses := make([]gin.H, 0, len(upstreams))

	for _, u := range upstreams {
		cache, hasCache := h.state.GetLatestCache(u.ID)
		status := gin.H{
			"id":                           u.ID,
			"name":                         u.Name,
			"type":                         u.Type,
			"content_mode":                 u.ContentMode,
			"subscription_format":          u.SubscriptionFormat,
			"clash_config":                 u.ClashConfig,
			"merge_config":                 u.MergeConfig,
			"enabled":                      u.Enabled,
			"cache_strategy":               u.CacheStrategy,
			"refresh_interval":             u.RefreshInterval,
			"has_cache":                    hasCache,
			"cache_variants":               h.state.CacheVariantCount(u.ID),
			"configured":                   u.APIEndpoint != "" || (u.Type == store.UpstreamTypeMerge && len(u.MergeConfig.Sources) > 0),
			"node_status_api_endpoint":     u.NodeStatusAPIEndpoint,
			"node_status_refresh_interval": u.NodeStatusRefreshInterval,
		}

		status["node_status"] = h.buildNodeStatusPayload(u, false)

		if hasCache {
			used := cache.TrafficStatus.UsedUpload + cache.TrafficStatus.UsedDownload
			daysUntilReset := cache.TrafficStatus.ResetDay
			if daysUntilReset < 0 {
				daysUntilReset = 0
			}
			status["cache_updated_at"] = cache.UpdatedAt.Format(time.RFC3339)
			status["traffic"] = gin.H{
				"plan_name":        cache.TrafficStatus.PlanName,
				"expired_at":       cache.TrafficStatus.ExpiredAt,
				"reset_day":        cache.TrafficStatus.ResetDay,
				"days_until_reset": daysUntilReset,
				"used_upload":      cache.TrafficStatus.UsedUpload,
				"used_download":    cache.TrafficStatus.UsedDownload,
				"used_total":       used,
				"transfer_enable":  cache.TrafficStatus.TransferEnable,
				"usage_text":       fmt.Sprintf("%s / %s", formatBytes(used), formatBytes(cache.TrafficStatus.TransferEnable)),
				"expiry_text":      formatExpiry(cache.TrafficStatus.ExpiredAt, cache.TrafficStatus.ResetDay),
				"subscribe_source": cache.SourceURL,
			}
		}
		upstreamStatuses = append(upstreamStatuses, status)
	}

	c.JSON(http.StatusOK, gin.H{
		"current_user":   currentUser,
		"upstreams":      upstreamStatuses,
		"upstream_count": len(upstreams),
		"key_count":      len(filteredKeys),
		"log_count":      len(filteredLogs),
		"global_config":  h.state.GetGlobalConfig(),
	})
}

func (h *SubscribeHandler) AdminGetUpstreamNodeStatus(c *gin.Context) {
	upstreamID := strings.TrimSpace(c.Param("id"))
	if !h.ensureUpstreamAccess(c, upstreamID) {
		return
	}
	upstream, ok := h.state.GetUpstream(upstreamID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "上游不存在"})
		return
	}
	if strings.TrimSpace(upstream.NodeStatusAPIEndpoint) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该上游未配置节点状态API"})
		return
	}
	c.JSON(http.StatusOK, h.buildNodeStatusPayload(upstream, true))
}

func (h *SubscribeHandler) AdminRefreshUpstreamNodeStatus(c *gin.Context) {
	upstreamID := strings.TrimSpace(c.Param("id"))
	if !h.ensureUpstreamAccess(c, upstreamID) {
		return
	}
	upstream, ok := h.state.GetUpstream(upstreamID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "上游不存在"})
		return
	}
	if strings.TrimSpace(upstream.NodeStatusAPIEndpoint) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该上游未配置节点状态API"})
		return
	}
	started := h.triggerNodeStatusRefresh(upstream, "manual")
	c.JSON(http.StatusOK, gin.H{"ok": true, "started": started, "upstream_id": upstreamID})
}

func (h *SubscribeHandler) AdminCacheStatus(c *gin.Context) {
	upstreams := h.filterUpstreamsByCurrentUser(c, h.state.ListUpstreams())
	upstreamStatuses := make([]gin.H, 0, len(upstreams))
	for _, u := range upstreams {
		uaStats := h.state.GetUpstreamUACacheStatuses(u.ID)
		latestCache, hasCache := h.state.GetLatestCache(u.ID)
		items := make([]gin.H, 0, len(uaStats))
		for _, item := range uaStats {
			displayUA := item.UserAgent
			if item.IsDefault {
				displayUA = "默认UA"
			}
			entry := gin.H{
				"user_agent":         item.UserAgent,
				"display_user_agent": displayUA,
				"is_default":         item.IsDefault,
				"has_cache":          item.HasCache,
				"total_requests":     item.TotalRequests,
				"today_requests":     item.TodayRequests,
				"month_requests":     item.MonthRequests,
			}
			if item.CacheUpdatedAt != nil {
				entry["cache_updated_at"] = item.CacheUpdatedAt.Format(time.RFC3339)
			}
			if item.LastSeenAt != nil {
				entry["last_seen_at"] = item.LastSeenAt.Format(time.RFC3339)
			}
			items = append(items, entry)
		}

		entry := gin.H{
			"id":                u.ID,
			"name":              u.Name,
			"enabled":           u.Enabled,
			"cache_strategy":    u.CacheStrategy,
			"refresh_interval":  u.RefreshInterval,
			"has_cache":         hasCache,
			"cache_variants":    h.state.CacheVariantCount(u.ID),
			"ua_count":          len(items),
			"ua_cache_statuses": items,
		}
		if hasCache {
			entry["cache_updated_at"] = latestCache.UpdatedAt.Format(time.RFC3339)
		}
		upstreamStatuses = append(upstreamStatuses, entry)
	}

	c.JSON(http.StatusOK, gin.H{"upstreams": upstreamStatuses})
}

func (h *SubscribeHandler) AdminListUpstreams(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"upstreams": h.filterUpstreamsByCurrentUser(c, h.state.ListUpstreams())})
}

func (h *SubscribeHandler) AdminAddUpstream(c *gin.Context) {
	currentUser, ok := h.state.GetAdminUser(h.currentAdminUserID(c))
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录或登录已过期"})
		return
	}
	if strings.TrimSpace(currentUser.UpstreamScopeMode) == store.UpstreamScopeModeSelected {
		c.JSON(http.StatusForbidden, gin.H{"error": "仅全上游权限用户可创建上游"})
		return
	}

	var req upstreamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	upstream := store.Upstream{
		Name:                      strings.TrimSpace(req.Name),
		Type:                      strings.TrimSpace(req.Type),
		ContentMode:               strings.TrimSpace(req.ContentMode),
		SubscriptionFormat:        strings.TrimSpace(req.SubscriptionFormat),
		ClashConfig:               req.ClashConfig,
		MergeConfig:               req.MergeConfig,
		APIEndpoint:               strings.TrimSpace(req.APIEndpoint),
		NodeStatusAPIEndpoint:     strings.TrimSpace(req.NodeStatusAPIEndpoint),
		NodeStatusRefreshInterval: strings.TrimSpace(req.NodeStatusRefreshInterval),
		Authorization:             strings.TrimSpace(req.Authorization),
		RequestUserAgent:          strings.TrimSpace(req.RequestUserAgent),
		Host:                      strings.TrimSpace(req.Host),
		Origin:                    strings.TrimSpace(req.Origin),
		Referer:                   strings.TrimSpace(req.Referer),
		CustomHeaders:             req.CustomHeaders,
		RefreshInterval:           req.RefreshInterval,
		CacheStrategy:             req.CacheStrategy,
		Enabled:                   true,
	}
	if err := h.state.AddUpstream(upstream); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	newUpstreams := h.state.ListUpstreams()
	for _, u := range newUpstreams {
		if u.Name == upstream.Name && u.Enabled && u.CacheStrategy == store.CacheStrategyForce {
			go h.runUpstreamRefreshLoop(u.ID)
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminUpdateUpstream(c *gin.Context) {
	upstreamID := c.Param("id")
	if !h.ensureUpstreamAccess(c, upstreamID) {
		return
	}
	existing, ok := h.state.GetUpstream(upstreamID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "上游不存在"})
		return
	}

	var req upstreamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}

	existing.Name = strings.TrimSpace(req.Name)
	existing.Type = strings.TrimSpace(req.Type)
	existing.ContentMode = strings.TrimSpace(req.ContentMode)
	existing.SubscriptionFormat = strings.TrimSpace(req.SubscriptionFormat)
	existing.ClashConfig = req.ClashConfig
	existing.MergeConfig = req.MergeConfig
	existing.APIEndpoint = strings.TrimSpace(req.APIEndpoint)
	existing.NodeStatusAPIEndpoint = strings.TrimSpace(req.NodeStatusAPIEndpoint)
	existing.NodeStatusRefreshInterval = strings.TrimSpace(req.NodeStatusRefreshInterval)
	existing.Authorization = strings.TrimSpace(req.Authorization)
	existing.RequestUserAgent = strings.TrimSpace(req.RequestUserAgent)
	existing.Host = strings.TrimSpace(req.Host)
	existing.Origin = strings.TrimSpace(req.Origin)
	existing.Referer = strings.TrimSpace(req.Referer)
	existing.CustomHeaders = req.CustomHeaders
	existing.RefreshInterval = req.RefreshInterval
	existing.CacheStrategy = req.CacheStrategy
	existing.Enabled = req.Enabled

	if err := h.state.UpdateUpstream(existing); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.clearNodeStatusCache(upstreamID)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminDeleteUpstream(c *gin.Context) {
	upstreamID := c.Param("id")
	if !h.ensureUpstreamAccess(c, upstreamID) {
		return
	}
	if err := h.state.DeleteUpstream(upstreamID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.clearNodeStatusCache(upstreamID)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminRefreshUpstream(c *gin.Context) {
	upstreamID := c.Param("id")
	if !h.ensureUpstreamAccess(c, upstreamID) {
		return
	}
	if err := h.RefreshUpstreamCache(upstreamID, "manual", ""); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if err := h.refreshActiveUAVariants(upstreamID, "manual-active"); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminDedupeUpstreamCache(c *gin.Context) {
	upstreamID := c.Param("id")
	if !h.ensureUpstreamAccess(c, upstreamID) {
		return
	}
	removed, remain := h.state.DedupeCacheVariants(upstreamID)
	c.JSON(http.StatusOK, gin.H{"ok": true, "removed": removed, "remain": remain})
}

func (h *SubscribeHandler) AdminDeleteUpstreamUACache(c *gin.Context) {
	upstreamID := strings.TrimSpace(c.Param("id"))
	if !h.ensureUpstreamAccess(c, upstreamID) {
		return
	}
	userAgent := strings.TrimSpace(c.Query("ua"))
	if userAgent == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少ua参数"})
		return
	}

	removedCache, removedPlan, variantKey, err := h.state.DeleteUACacheVariant(upstreamID, userAgent)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !removedCache && !removedPlan {
		c.JSON(http.StatusNotFound, gin.H{"error": "未找到对应UA缓存"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"variant":       variantKey,
		"removed_cache": removedCache,
		"removed_plan":  removedPlan,
	})
}

func (h *SubscribeHandler) AdminGetSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"global_config": h.state.GetGlobalConfig(),
		"upstreams":     h.filterUpstreamsByCurrentUser(c, h.state.ListUpstreams()),
	})
}

func (h *SubscribeHandler) AdminUpdateSettings(c *gin.Context) {
	var req globalConfigRequest
	// Use custom JSON decoder to reject unknown fields
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	if err := h.state.UpdateGlobalConfig(store.GlobalConfig{LogRetentionDays: req.LogRetentionDays, ActiveUADays: req.ActiveUADays, UANormalization: req.UANormalization}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存配置失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminExportUARules(c *gin.Context) {
	config := h.state.GetGlobalConfig().UANormalization
	fileName := fmt.Sprintf("ua-rules-%s.json", time.Now().Format("20060102-150405"))
	payload := gin.H{
		"enabled":             config.Enabled,
		"unknown_passthrough": config.UnknownPassthrough,
		"rules":               config.Rules,
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	c.JSON(http.StatusOK, payload)
}

func (h *SubscribeHandler) AdminImportUARules(c *gin.Context) {
	var req uaRulesImportRequest
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "规则文件格式错误"})
		return
	}

	current := h.state.GetGlobalConfig()
	uaConfig := current.UANormalization
	if req.Enabled != nil {
		uaConfig.Enabled = *req.Enabled
	}
	if req.UnknownPassthrough != nil {
		uaConfig.UnknownPassthrough = *req.UnknownPassthrough
	}
	if req.Rules == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少rules字段"})
		return
	}
	uaConfig.Rules = req.Rules

	if err := h.state.UpdateGlobalConfig(store.GlobalConfig{
		LogRetentionDays: current.LogRetentionDays,
		ActiveUADays:     current.ActiveUADays,
		UANormalization:  uaConfig,
	}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"imported": len(uaConfig.Rules),
	})
}

func (h *SubscribeHandler) AdminExportGlobalConfig(c *gin.Context) {
	global := h.state.GetGlobalConfig()
	fileName := fmt.Sprintf("global-config-%s.json", time.Now().Format("20060102-150405"))
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	c.JSON(http.StatusOK, gin.H{
		"global_config": global,
	})
}

func (h *SubscribeHandler) AdminImportGlobalConfig(c *gin.Context) {
	var req globalConfigImportRequest
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "配置文件格式错误"})
		return
	}

	var target store.GlobalConfig
	if req.GlobalConfig != nil {
		target = store.GlobalConfig{
			LogRetentionDays: req.GlobalConfig.LogRetentionDays,
			ActiveUADays:     req.GlobalConfig.ActiveUADays,
			UANormalization:  req.GlobalConfig.UANormalization,
		}
	} else {
		current := h.state.GetGlobalConfig()
		target = current
		if req.LogRetentionDays != nil {
			target.LogRetentionDays = *req.LogRetentionDays
		}
		if req.ActiveUADays != nil {
			target.ActiveUADays = *req.ActiveUADays
		}
		if req.UANormalization != nil {
			target.UANormalization = *req.UANormalization
		}
	}

	if err := h.state.UpdateGlobalConfig(target); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"global_config": h.state.GetGlobalConfig(),
	})
}

func (h *SubscribeHandler) AdminListKeys(c *gin.Context) {
	keys := h.filterKeysByCurrentUser(c, h.state.ListKeys())
	upstreams := h.filterUpstreamsByCurrentUser(c, h.state.ListUpstreams())
	upstreamMap := make(map[string]string)
	for _, u := range upstreams {
		upstreamMap[u.ID] = u.Name
	}

	result := make([]gin.H, 0, len(keys))
	for _, k := range keys {
		result = append(result, gin.H{
			"id":            k.ID,
			"key":           k.Key,
			"name":          k.Name,
			"upstream_id":   k.UpstreamID,
			"upstream_name": upstreamMap[k.UpstreamID],
			"enabled":       k.Enabled,
			"created_at":    k.CreatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"keys": result})
}

func (h *SubscribeHandler) AdminAddKey(c *gin.Context) {
	var req addKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	upstreamID := strings.TrimSpace(req.UpstreamID)
	if upstreamID == "" {
		allowedUpstreams := h.filterUpstreamsByCurrentUser(c, h.state.ListUpstreams())
		if len(allowedUpstreams) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "当前用户无可用上游"})
			return
		}
		upstreamID = allowedUpstreams[0].ID
	}
	if !h.ensureUpstreamAccess(c, upstreamID) {
		return
	}
	if err := h.state.AddKey(strings.TrimSpace(req.Key), strings.TrimSpace(req.Name), upstreamID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminUpdateKey(c *gin.Context) {
	keyID := c.Param("id")
	var req updateKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	keys := h.state.ListKeys()
	var currentKey *store.AccessKey
	for i := range keys {
		if keys[i].ID == keyID {
			currentKey = &keys[i]
			break
		}
	}
	if currentKey == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "key不存在"})
		return
	}
	if !h.ensureUpstreamAccess(c, currentKey.UpstreamID) {
		return
	}
	targetUpstreamID := strings.TrimSpace(req.UpstreamID)
	if targetUpstreamID != "" && !h.ensureUpstreamAccess(c, targetUpstreamID) {
		return
	}
	if err := h.state.UpdateKey(keyID, strings.TrimSpace(req.Name), req.Enabled, targetUpstreamID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminDeleteKey(c *gin.Context) {
	keyID := c.Param("id")
	keys := h.state.ListKeys()
	for _, key := range keys {
		if key.ID != keyID {
			continue
		}
		if !h.ensureUpstreamAccess(c, key.UpstreamID) {
			return
		}
		break
	}
	if err := h.state.DeleteKey(keyID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) currentAdminUserID(c *gin.Context) string {
	value, exists := c.Get(middleware.ContextAdminUserID)
	if !exists {
		return ""
	}
	userID, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(userID)
}

func (h *SubscribeHandler) currentAdminRole(c *gin.Context) string {
	value, exists := c.Get(middleware.ContextAdminRole)
	if !exists {
		return ""
	}
	role, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(role)
}

func (h *SubscribeHandler) currentAdminUsername(c *gin.Context) string {
	value, exists := c.Get(middleware.ContextAdminUsername)
	if !exists {
		return ""
	}
	username, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(username)
}

func (h *SubscribeHandler) currentAdminUser(c *gin.Context) gin.H {
	userID := h.currentAdminUserID(c)
	allowedUpstreamIDs := h.state.UserAllowedUpstreamIDs(userID)
	allowedUpstreamList := make([]string, 0, len(allowedUpstreamIDs))
	for upstreamID := range allowedUpstreamIDs {
		allowedUpstreamList = append(allowedUpstreamList, upstreamID)
	}
	sort.Strings(allowedUpstreamList)

	permissions := h.state.EffectivePermissions(userID)
	user, _ := h.state.GetAdminUser(userID)
	scopeMode := strings.TrimSpace(user.UpstreamScopeMode)
	if scopeMode == "" {
		scopeMode = store.UpstreamScopeModeAll
	}

	return gin.H{
		"id":                    userID,
		"username":              h.currentAdminUsername(c),
		"role":                  h.currentAdminRole(c),
		"effective_permissions": permissions,
		"custom_permissions":    user.CustomPermissions,
		"upstream_scope_mode":   scopeMode,
		"upstream_scope_ids":    user.UpstreamScopeIDs,
		"allowed_upstream_ids":  allowedUpstreamList,
	}
}

func (h *SubscribeHandler) currentAllowedUpstreamIDs(c *gin.Context) map[string]struct{} {
	return h.state.UserAllowedUpstreamIDs(h.currentAdminUserID(c))
}

func (h *SubscribeHandler) filterUpstreamsByCurrentUser(c *gin.Context, upstreams []store.Upstream) []store.Upstream {
	allowed := h.currentAllowedUpstreamIDs(c)
	result := make([]store.Upstream, 0, len(upstreams))
	for _, upstream := range upstreams {
		if _, ok := allowed[upstream.ID]; !ok {
			continue
		}
		result = append(result, upstream)
	}
	return result
}

func (h *SubscribeHandler) filterKeysByCurrentUser(c *gin.Context, keys []store.AccessKey) []store.AccessKey {
	allowed := h.currentAllowedUpstreamIDs(c)
	result := make([]store.AccessKey, 0, len(keys))
	for _, key := range keys {
		if _, ok := allowed[key.UpstreamID]; !ok {
			continue
		}
		result = append(result, key)
	}
	return result
}

func (h *SubscribeHandler) ensureUpstreamAccess(c *gin.Context, upstreamID string) bool {
	if h.state.UserCanAccessUpstream(h.currentAdminUserID(c), strings.TrimSpace(upstreamID)) {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "无该上游访问权限"})
	return false
}

func permissionsToSet(permissions []string) map[string]struct{} {
	result := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		normalized := strings.TrimSpace(permission)
		if normalized == "" {
			continue
		}
		result[normalized] = struct{}{}
	}
	return result
}

func (h *SubscribeHandler) canGrantUserPolicy(c *gin.Context, role string, customPermissions []string, scopeMode string, scopeIDs []string) error {
	callerUserID := h.currentAdminUserID(c)
	callerUser, ok := h.state.GetAdminUser(callerUserID)
	if !ok {
		return errors.New("当前用户不存在")
	}

	callerPermissionSet := permissionsToSet(h.state.EffectivePermissions(callerUserID))
	targetPermissionSet := permissionsToSet(store.RolePresetPermissions(strings.TrimSpace(role)))
	for permission := range permissionsToSet(customPermissions) {
		targetPermissionSet[permission] = struct{}{}
	}

	for permission := range targetPermissionSet {
		if _, ok := callerPermissionSet[permission]; ok {
			continue
		}
		return errors.New("不能授予超出自身权限的功能")
	}

	normalizedMode := strings.TrimSpace(scopeMode)
	if normalizedMode == "" {
		normalizedMode = store.UpstreamScopeModeAll
	}
	if callerUser.UpstreamScopeMode != store.UpstreamScopeModeAll {
		if normalizedMode == store.UpstreamScopeModeAll {
			return errors.New("不能授予全上游访问权限")
		}
		callerAllowed := h.currentAllowedUpstreamIDs(c)
		for _, upstreamID := range scopeIDs {
			if _, ok := callerAllowed[strings.TrimSpace(upstreamID)]; ok {
				continue
			}
			return errors.New("不能授予超出自身范围的上游")
		}
	}

	return nil
}

func (h *SubscribeHandler) AdminListUsers(c *gin.Context) {
	users := h.state.ListAdminUsers()
	result := make([]gin.H, 0, len(users))
	for _, user := range users {
		effectivePermissions := store.RolePresetPermissions(user.Role)
		customPermissions := append([]string(nil), user.CustomPermissions...)
		if len(customPermissions) > 0 {
			effectiveSet := make(map[string]struct{}, len(effectivePermissions)+len(customPermissions))
			for _, permission := range effectivePermissions {
				effectiveSet[permission] = struct{}{}
			}
			for _, permission := range customPermissions {
				effectiveSet[permission] = struct{}{}
			}
			effectivePermissions = make([]string, 0, len(effectiveSet))
			for permission := range effectiveSet {
				effectivePermissions = append(effectivePermissions, permission)
			}
			sort.Strings(effectivePermissions)
		}
		scopeMode := user.UpstreamScopeMode
		if strings.TrimSpace(scopeMode) == "" {
			scopeMode = store.UpstreamScopeModeAll
		}
		result = append(result, gin.H{
			"id":                    user.ID,
			"username":              user.Username,
			"role":                  user.Role,
			"enabled":               user.Enabled,
			"custom_permissions":    customPermissions,
			"effective_permissions": effectivePermissions,
			"upstream_scope_mode":   scopeMode,
			"upstream_scope_ids":    user.UpstreamScopeIDs,
			"created_at":            user.CreatedAt,
			"updated_at":            user.UpdatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"users":                result,
		"all_permissions":      store.AllPermissions(),
		"role_permissions":     gin.H{"super_admin": store.RolePresetPermissions(store.AdminRoleSuperAdmin), "operator": store.RolePresetPermissions(store.AdminRoleOperator), "viewer": store.RolePresetPermissions(store.AdminRoleViewer)},
		"upstream_scope_modes": []string{store.UpstreamScopeModeAll, store.UpstreamScopeModeSelected},
		"upstreams":            h.filterUpstreamsByCurrentUser(c, h.state.ListUpstreams()),
	})
}

func (h *SubscribeHandler) AdminAddUser(c *gin.Context) {
	var req addUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	if err := h.canGrantUserPolicy(c, strings.TrimSpace(req.Role), req.CustomPermissions, strings.TrimSpace(req.UpstreamScopeMode), req.UpstreamScopeIDs); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	if err := h.state.AddAdminUser(
		strings.TrimSpace(req.Username),
		req.Password,
		strings.TrimSpace(req.Role),
		req.CustomPermissions,
		strings.TrimSpace(req.UpstreamScopeMode),
		req.UpstreamScopeIDs,
	); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminUpdateUser(c *gin.Context) {
	userID := strings.TrimSpace(c.Param("id"))
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户ID不能为空"})
		return
	}
	var req updateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	currentUserID := h.currentAdminUserID(c)
	if currentUserID != "" && currentUserID == userID && !req.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不能禁用当前登录用户"})
		return
	}
	if err := h.canGrantUserPolicy(c, strings.TrimSpace(req.Role), req.CustomPermissions, strings.TrimSpace(req.UpstreamScopeMode), req.UpstreamScopeIDs); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	if err := h.state.UpdateAdminUser(
		userID,
		strings.TrimSpace(req.Username),
		strings.TrimSpace(req.Role),
		req.Enabled,
		req.CustomPermissions,
		strings.TrimSpace(req.UpstreamScopeMode),
		req.UpstreamScopeIDs,
	); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminUpdateUserPassword(c *gin.Context) {
	userID := strings.TrimSpace(c.Param("id"))
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户ID不能为空"})
		return
	}
	var req updateUserPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	if err := h.state.UpdateAdminUserPassword(userID, req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminDeleteUser(c *gin.Context) {
	userID := strings.TrimSpace(c.Param("id"))
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户ID不能为空"})
		return
	}
	currentUserID := h.currentAdminUserID(c)
	if currentUserID != "" && currentUserID == userID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不能删除当前登录用户"})
		return
	}
	if err := h.state.DeleteAdminUser(userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminGetLogs(c *gin.Context) {
	page := 1
	pageSize := 50

	if raw := c.Query("page"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if raw := c.Query("page_size"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			pageSize = parsed
		}
	}

	allowedUpstreamIDs := h.currentAllowedUpstreamIDs(c)
	if raw := c.Query("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			c.JSON(http.StatusOK, gin.H{"logs": h.state.ListLogsByUpstreamScope(parsed, allowedUpstreamIDs)})
			return
		}
	}

	result := h.state.ListLogsPaginatedByUpstreamScope(page, pageSize, allowedUpstreamIDs)
	c.JSON(http.StatusOK, result)
}

func (h *SubscribeHandler) AdminManualRefresh(c *gin.Context) {
	upstreams := h.filterUpstreamsByCurrentUser(c, h.state.ListUpstreams())
	var lastErr error
	refreshed := 0
	for _, u := range upstreams {
		if u.Enabled {
			if err := h.RefreshUpstreamCache(u.ID, "manual", ""); err != nil {
				lastErr = err
			} else {
				refreshed++
			}
			if err := h.refreshActiveUAVariants(u.ID, "manual-active"); err != nil {
				lastErr = err
			}
		}
	}
	if refreshed == 0 && lastErr != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": lastErr.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "refreshed": refreshed})
}

func (h *SubscribeHandler) appendClientLog(keyID, _ string, keyName, upstreamID, clientIP, userAgent string, uaDetails store.UAMatchDetails, cacheHit bool, status, message string) {
	entry := store.ClientUpdateLog{
		Time:        time.Now(),
		KeyID:       keyID,
		Key:         "",
		KeyName:     keyName,
		UpstreamID:  upstreamID,
		ClientIP:    clientIP,
		UserAgent:   userAgent,
		UARule:      uaDetails.Rule,
		UAVariant:   uaDetails.Variant,
		UAFamily:    uaDetails.Family,
		CacheBucket: uaDetails.CacheBucket,
		CacheHit:    cacheHit,
		Status:      status,
		Message:     message,
	}
	if err := h.state.AppendClientLog(entry); err != nil {
		log.Printf("写入客户端日志失败: %v", err)
	}
}

func (h *SubscribeHandler) shouldUseSecureCookie(c *gin.Context) bool {
	if c.Request != nil && c.Request.TLS != nil {
		return true
	}
	proto := strings.ToLower(strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")))
	return proto == "https"
}

func (h *SubscribeHandler) allowAdminLogin(clientIP string) (bool, int) {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()

	if strings.TrimSpace(clientIP) == "" {
		return true, 0
	}

	attempt, ok := h.loginAttempts[clientIP]
	if !ok {
		return true, 0
	}

	now := time.Now()
	if now.After(attempt.blockedUntil) {
		if now.Sub(attempt.lastFailedAt) > loginFailureWindow {
			delete(h.loginAttempts, clientIP)
			return true, 0
		}
		return true, 0
	}

	retryAfter := int(attempt.blockedUntil.Sub(now).Seconds())
	if retryAfter < 1 {
		retryAfter = 1
	}
	return false, retryAfter
}

func (h *SubscribeHandler) recordAdminLoginFailure(clientIP string) {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()

	if strings.TrimSpace(clientIP) == "" {
		return
	}

	now := time.Now()
	attempt := h.loginAttempts[clientIP]
	if now.Sub(attempt.lastFailedAt) > loginFailureWindow {
		attempt.failed = 0
		attempt.blockedUntil = time.Time{}
	}
	attempt.failed++
	attempt.lastFailedAt = now
	if attempt.failed >= maxLoginFailures {
		attempt.blockedUntil = now.Add(loginBlockDuration)
		attempt.failed = 0
	}
	h.loginAttempts[clientIP] = attempt
}

func (h *SubscribeHandler) recordAdminLoginSuccess(clientIP string) {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()
	if strings.TrimSpace(clientIP) == "" {
		return
	}
	delete(h.loginAttempts, clientIP)
}

func copyHeaders(src map[string][]string, dst http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func filterAllowedPassthroughHeaders(src map[string][]string) map[string][]string {
	dst := make(map[string][]string)
	for key, values := range src {
		if _, ok := passthroughHeaderWhitelist[strings.ToLower(strings.TrimSpace(key))]; !ok {
			continue
		}
		if len(values) == 0 {
			continue
		}
		dst[key] = append([]string(nil), values...)
	}
	return dst
}

func mergeAllowedPassthroughHeadersFromMap(dst map[string][]string, src map[string][]string) {
	if len(src) == 0 {
		return
	}
	for key, values := range src {
		if _, ok := passthroughHeaderWhitelist[strings.ToLower(strings.TrimSpace(key))]; !ok {
			continue
		}
		if len(values) == 0 {
			continue
		}
		if _, exists := getHeaderValues(dst, key); exists {
			continue
		}
		dst[key] = append([]string(nil), values...)
	}
}

func setHeaderValues(dst map[string][]string, key string, values []string) {
	if dst == nil {
		return
	}
	for existingKey := range dst {
		if strings.EqualFold(strings.TrimSpace(existingKey), key) {
			dst[existingKey] = append([]string(nil), values...)
			return
		}
	}
	dst[key] = append([]string(nil), values...)
}

func deleteHeader(dst map[string][]string, key string) {
	if dst == nil {
		return
	}
	for existingKey := range dst {
		if strings.EqualFold(strings.TrimSpace(existingKey), key) {
			delete(dst, existingKey)
		}
	}
}

func getHeaderValues(src map[string][]string, key string) ([]string, bool) {
	for existingKey, values := range src {
		if strings.EqualFold(strings.TrimSpace(existingKey), key) {
			return values, true
		}
	}
	return nil, false
}

func ensureTrafficMetadataHeaders(headers map[string][]string, traffic store.TrafficStatus) {
	if headers == nil {
		return
	}
	if _, ok := getHeaderValues(headers, "subscription-userinfo"); !ok {
		if value := buildSubscriptionUserInfoValue(traffic); value != "" {
			setHeaderValues(headers, "subscription-userinfo", []string{value})
		}
	}
}

func buildSubscriptionUserInfoValue(traffic store.TrafficStatus) string {
	hasTraffic := traffic.TransferEnable > 0 || traffic.UsedUpload > 0 || traffic.UsedDownload > 0 || traffic.ExpiredAt > 0
	if !hasTraffic {
		return ""
	}
	parts := []string{
		fmt.Sprintf("upload=%d", traffic.UsedUpload),
		fmt.Sprintf("download=%d", traffic.UsedDownload),
		fmt.Sprintf("total=%d", traffic.TransferEnable),
	}
	if traffic.ExpiredAt > 0 {
		parts = append(parts, fmt.Sprintf("expire=%d", traffic.ExpiredAt))
	}
	return strings.Join(parts, "; ")
}

func mergeTrafficStatus(target *store.TrafficStatus, incoming store.TrafficStatus) {
	if target == nil {
		return
	}
	target.UsedUpload += incoming.UsedUpload
	target.UsedDownload += incoming.UsedDownload
	target.TransferEnable += incoming.TransferEnable
	if target.PlanName == "" && strings.TrimSpace(incoming.PlanName) != "" {
		target.PlanName = incoming.PlanName
	}
	if incoming.ExpiredAt > 0 && (target.ExpiredAt <= 0 || incoming.ExpiredAt < target.ExpiredAt) {
		target.ExpiredAt = incoming.ExpiredAt
	}
	if incoming.ResetDay > 0 && (target.ResetDay <= 0 || incoming.ResetDay < target.ResetDay) {
		target.ResetDay = incoming.ResetDay
	}
}

func mergeAllowedPassthroughHeaders(dst map[string][]string, src http.Header) {
	for key, values := range src {
		if _, ok := passthroughHeaderWhitelist[strings.ToLower(strings.TrimSpace(key))]; !ok {
			continue
		}
		if len(values) == 0 {
			continue
		}
		if _, exists := dst[key]; exists {
			continue
		}
		dst[key] = append([]string(nil), values...)
	}
}

func buildUpstreamRequestHeaders(upstream store.Upstream) map[string]string {
	headers := map[string]string{}
	if upstream.Authorization != "" {
		headers["Authorization"] = upstream.Authorization
	}
	if upstream.RequestUserAgent != "" {
		headers["User-Agent"] = upstream.RequestUserAgent
	}
	if upstream.Host != "" {
		headers["Host"] = upstream.Host
	}
	if upstream.Origin != "" {
		headers["Origin"] = upstream.Origin
	}
	if upstream.Referer != "" {
		headers["Referer"] = upstream.Referer
	}
	for key, value := range upstream.CustomHeaders {
		if key != "" && value != "" {
			headers[key] = value
		}
	}
	return headers
}

func (h *SubscribeHandler) triggerNodeStatusRefresh(upstream store.Upstream, reason string) bool {
	upstreamID := strings.TrimSpace(upstream.ID)
	if upstreamID == "" {
		return false
	}

	h.nodeStatusMu.Lock()
	if h.nodeStatusRunning[upstreamID] {
		h.nodeStatusMu.Unlock()
		return false
	}
	h.nodeStatusRunning[upstreamID] = true
	h.nodeStatusMu.Unlock()

	go func() {
		nodes, total, online, err := h.fetchUpstreamNodeStatus(upstream)
		now := time.Now()

		h.nodeStatusMu.Lock()
		entry := h.nodeStatusCache[upstreamID]
		if err != nil {
			entry.LastError = err.Error()
			if entry.FetchedAt.IsZero() {
				entry.FetchedAt = now
			}
			log.Printf("节点状态刷新失败 upstream=%s reason=%s: %v", upstreamID, reason, err)
		} else {
			entry.Nodes = nodes
			entry.Total = total
			entry.Online = online
			entry.FetchedAt = now
			entry.ExpiresAt = now.Add(nodeStatusCacheTTL)
			entry.LastError = ""
			log.Printf("节点状态刷新成功 upstream=%s reason=%s total=%d online=%d", upstreamID, reason, total, online)
		}
		h.nodeStatusCache[upstreamID] = entry
		delete(h.nodeStatusRunning, upstreamID)
		h.nodeStatusMu.Unlock()
	}()

	return true
}

func (h *SubscribeHandler) buildNodeStatusPayload(upstream store.Upstream, includeNodes bool) gin.H {
	upstreamID := strings.TrimSpace(upstream.ID)
	h.nodeStatusMu.RLock()
	entry, hasCache := h.nodeStatusCache[upstreamID]
	isRunning := h.nodeStatusRunning[upstreamID]
	h.nodeStatusMu.RUnlock()

	payload := gin.H{
		"configured":                   strings.TrimSpace(upstream.NodeStatusAPIEndpoint) != "",
		"cache_ttl_seconds":            int(nodeStatusCacheTTL.Seconds()),
		"node_status_refresh_interval": upstream.NodeStatusRefreshInterval,
		"is_refreshing":                isRunning,
		"has_cache":                    hasCache,
		"stale":                        true,
		"total_nodes":                  0,
		"online_nodes":                 0,
		"online_rate":                  0.0,
	}

	if !hasCache {
		if includeNodes {
			payload["nodes"] = make([]gin.H, 0)
		}
		return payload
	}

	payload["total_nodes"] = entry.Total
	payload["online_nodes"] = entry.Online
	if entry.Total > 0 {
		payload["online_rate"] = float64(entry.Online) * 100 / float64(entry.Total)
	}
	payload["fetched_at"] = entry.FetchedAt.Format(time.RFC3339)
	if !entry.ExpiresAt.IsZero() {
		payload["expires_at"] = entry.ExpiresAt.Format(time.RFC3339)
		payload["stale"] = time.Now().After(entry.ExpiresAt)
	}
	if entry.LastError != "" {
		payload["fetch_error"] = entry.LastError
	}
	if includeNodes {
		payload["nodes"] = entry.Nodes
	}

	return payload
}

func (h *SubscribeHandler) clearNodeStatusCache(upstreamID string) {
	upstreamID = strings.TrimSpace(upstreamID)
	if upstreamID == "" {
		return
	}
	h.nodeStatusMu.Lock()
	delete(h.nodeStatusCache, upstreamID)
	delete(h.nodeStatusRunning, upstreamID)
	h.nodeStatusMu.Unlock()
}

func (h *SubscribeHandler) fetchUpstreamNodeStatus(upstream store.Upstream) ([]gin.H, int, int, error) {
	endpoint := strings.TrimSpace(upstream.NodeStatusAPIEndpoint)
	if endpoint == "" {
		return nil, 0, 0, nil
	}

	headers := buildUpstreamRequestHeaders(upstream)
	resp, err := h.httpClient.MakeRequest(http.MethodGet, endpoint, headers)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("请求节点状态API失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, 0, fmt.Errorf("节点状态API返回状态码: %d", resp.StatusCode)
	}

	var payload nodeStatusFetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, 0, 0, fmt.Errorf("解析节点状态响应失败: %w", err)
	}

	nodes := make([]gin.H, 0, len(payload.Data))
	onlineCount := 0
	for _, item := range payload.Data {
		id := normalizeNodeStatusID(item["id"])
		name := normalizeNodeStatusString(item["name"])
		nodeType := normalizeNodeStatusString(item["type"])
		host := normalizeNodeStatusString(item["host"])
		rate := normalizeNodeStatusString(item["rate"])
		isOnline := normalizeNodeStatusOnline(item["is_online"])
		lastCheckAt := normalizeNodeStatusUnix(item["last_check_at"])
		if isOnline {
			onlineCount++
		}

		node := gin.H{
			"id":            id,
			"name":          name,
			"type":          nodeType,
			"host":          host,
			"rate":          rate,
			"is_online":     isOnline,
			"last_check_at": lastCheckAt,
		}
		nodes = append(nodes, node)
	}

	return nodes, len(nodes), onlineCount, nil
}

func normalizeNodeStatusID(raw interface{}) string {
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case int:
		return strconv.Itoa(v)
	default:
		return ""
	}
}

func normalizeNodeStatusString(raw interface{}) string {
	if raw == nil {
		return ""
	}
	if value, ok := raw.(string); ok {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(fmt.Sprint(raw))
}

func normalizeNodeStatusOnline(raw interface{}) bool {
	switch v := raw.(type) {
	case bool:
		return v
	case float64:
		return int(v) != 0
	case int:
		return v != 0
	case int64:
		return v != 0
	case string:
		trimmed := strings.TrimSpace(strings.ToLower(v))
		if trimmed == "1" || trimmed == "true" || trimmed == "online" {
			return true
		}
		return false
	default:
		return false
	}
}

func normalizeNodeStatusUnix(raw interface{}) int64 {
	switch v := raw.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0
		}
		parsed, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return 0
		}
		return parsed
	default:
		return 0
	}
}

func formatBytes(v int64) string {
	if v < 0 {
		return "0B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	value := float64(v)
	idx := 0
	for value >= 1024 && idx < len(units)-1 {
		value /= 1024
		idx++
	}
	if idx == 0 {
		return fmt.Sprintf("%d%s", v, units[idx])
	}
	return fmt.Sprintf("%.2f%s", value, units[idx])
}

func formatExpiry(expiredAt int64, resetDay int) string {
	if resetDay < 0 {
		resetDay = 0
	}

	if expiredAt <= 0 {
		if resetDay > 0 {
			return fmt.Sprintf("下次重置: %d天后", resetDay)
		}
		return "未提供到期信息"
	}
	t := time.Unix(expiredAt, 0)
	if resetDay > 0 {
		return fmt.Sprintf("到期: %s / 下次重置: %d天后", t.Format("2006-01-02 15:04:05"), resetDay)
	}
	return "到期: " + t.Format("2006-01-02 15:04:05")
}
