package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"jsyproxy/config"
	staticfiles "jsyproxy/static"
	"jsyproxy/store"
	"jsyproxy/utils"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var passthroughHeaderWhitelist = map[string]struct{}{
	"subscription-userinfo":     {},
	"profile-web-page-url":      {},
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
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	APIEndpoint      string            `json:"api_endpoint"`
	Authorization    string            `json:"authorization"`
	RequestUserAgent string            `json:"request_user_agent"`
	Host             string            `json:"host"`
	Origin           string            `json:"origin"`
	Referer          string            `json:"referer"`
	CustomHeaders    map[string]string `json:"custom_headers"`
	RefreshInterval  string            `json:"refresh_interval"`
	CacheStrategy    string            `json:"cache_strategy"`
	Enabled          bool              `json:"enabled"`
}

type globalConfigRequest struct {
	LogRetentionDays int                         `json:"log_retention_days"`
	ActiveUADays     int                         `json:"active_ua_days"`
	UANormalization  store.UANormalizationConfig `json:"ua_normalization"`
}

type SubscribeHandler struct {
	config       *config.Config
	httpClient   *utils.HTTPClient
	state        *store.State
	refreshMutex sync.Map
}

// refreshLockValue holds the wait group for contended refreshes
type refreshLockValue struct {
	wg       sync.WaitGroup
	doneChan chan struct{}
}

const refreshContentionTimeout = 10 * time.Second

func NewSubscribeHandler(cfg *config.Config) (*SubscribeHandler, error) {
	state, err := store.New(cfg.DataFile, cfg.BootstrapAccessKeys, cfg.DefaultRefreshInterval)
	if err != nil {
		return nil, err
	}
	return &SubscribeHandler{config: cfg, httpClient: utils.NewHTTPClient(), state: state}, nil
}

func (h *SubscribeHandler) ValidateAdminSession(token string) bool {
	return h.state.ValidateAdminSession(token)
}

func (h *SubscribeHandler) StartAutoRefresh() {
	upstreams := h.state.ListUpstreams()
	for _, u := range upstreams {
		if u.Enabled && u.CacheStrategy == store.CacheStrategyForce {
			go h.runUpstreamRefreshLoop(u.ID)
		}
	}
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

	copyHeaders(cache.Headers, c.Writer.Header())
	c.Status(cache.StatusCode)
	if _, err := c.Writer.Write(cache.Body); err != nil {
		h.appendClientLog(keyInfo.ID, keyInfo.Key, keyInfo.Name, keyInfo.UpstreamID, clientIP, clientUA, uaDetails, cacheHit, "failed", "写响应失败")
		return
	}
	h.appendClientLog(keyInfo.ID, keyInfo.Key, keyInfo.Name, keyInfo.UpstreamID, clientIP, clientUA, uaDetails, cacheHit, "success", "")
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
		return errors.New("请先配置API端点地址")
	}

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

	resp, err := h.httpClient.MakeRequest(http.MethodGet, upstream.APIEndpoint, headers)
	if err != nil {
		return fmt.Errorf("请求上游API失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("上游API返回状态码: %d", resp.StatusCode)
	}

	var subscribeResp SubscribeResponse
	if err := utils.ParseJSONResponse(resp, &subscribeResp); err != nil {
		return fmt.Errorf("解析上游响应失败: %w", err)
	}
	if subscribeResp.Data.SubscribeURL == "" {
		return errors.New("上游响应缺少subscribe_url")
	}

	fetchUA := strings.TrimSpace(downstreamUA)
	if fetchUA == "" {
		fetchUA = upstream.RequestUserAgent
	}
	cacheVariantUA := strings.TrimSpace(downstreamUA)
	contentHeaders := map[string]string{}
	if fetchUA != "" {
		contentHeaders["User-Agent"] = fetchUA
	}
	contentResp, err := h.httpClient.MakeRequest(http.MethodGet, subscribeResp.Data.SubscribeURL, contentHeaders)
	if err != nil {
		return fmt.Errorf("请求订阅链接失败: %w", err)
	}
	defer contentResp.Body.Close()
	if contentResp.StatusCode != http.StatusOK {
		return fmt.Errorf("订阅内容返回状态码: %d", contentResp.StatusCode)
	}

	body, err := io.ReadAll(contentResp.Body)
	if err != nil {
		return fmt.Errorf("读取订阅内容失败: %w", err)
	}

	headersCopy := make(map[string][]string)
	for k, values := range contentResp.Header {
		headersCopy[k] = append([]string(nil), values...)
	}
	mergeAllowedPassthroughHeaders(headersCopy, resp.Header)

	h.state.SetCache(upstreamID, cacheVariantUA, &store.CachedSubscription{
		Body:       body,
		Headers:    headersCopy,
		StatusCode: contentResp.StatusCode,
		UpdatedAt:  time.Now(),
		SourceURL:  subscribeResp.Data.SubscribeURL,
		TrafficStatus: store.TrafficStatus{
			ExpiredAt:      subscribeResp.Data.ExpiredAt,
			UsedUpload:     subscribeResp.Data.U,
			UsedDownload:   subscribeResp.Data.D,
			TransferEnable: subscribeResp.Data.TransferEnable,
			PlanName:       subscribeResp.Data.Plan.Name,
			ResetDay:       subscribeResp.Data.ResetDay,
		},
	})

	log.Printf("订阅缓存刷新成功 upstream=%s reason=%s source=%s bytes=%d", upstreamID, reason, subscribeResp.Data.SubscribeURL, len(body))
	return nil
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
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	if req.Password != h.config.AdminPassword {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "密码错误"})
		return
	}
	token, err := h.state.CreateAdminSession()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
		return
	}
	c.SetCookie("admin_session", token, 86400, "/admin", "", false, true)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminLogout(c *gin.Context) {
	if token, err := c.Cookie("admin_session"); err == nil {
		h.state.DeleteAdminSession(token)
	}
	c.SetCookie("admin_session", "", -1, "/admin", "", false, true)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminStatus(c *gin.Context) {
	upstreams := h.state.ListUpstreams()
	upstreamStatuses := make([]gin.H, 0, len(upstreams))

	for _, u := range upstreams {
		cache, hasCache := h.state.GetLatestCache(u.ID)
		status := gin.H{
			"id":               u.ID,
			"name":             u.Name,
			"enabled":          u.Enabled,
			"cache_strategy":   u.CacheStrategy,
			"refresh_interval": u.RefreshInterval,
			"has_cache":        hasCache,
			"cache_variants":   h.state.CacheVariantCount(u.ID),
			"configured":       u.APIEndpoint != "",
		}

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
		"upstreams":      upstreamStatuses,
		"upstream_count": len(upstreams),
		"key_count":      len(h.state.ListKeys()),
		"log_count":      h.state.LogCount(),
		"global_config":  h.state.GetGlobalConfig(),
	})
}

func (h *SubscribeHandler) AdminCacheStatus(c *gin.Context) {
	upstreams := h.state.ListUpstreams()
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
	c.JSON(http.StatusOK, gin.H{"upstreams": h.state.ListUpstreams()})
}

func (h *SubscribeHandler) AdminAddUpstream(c *gin.Context) {
	var req upstreamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	upstream := store.Upstream{
		Name:             strings.TrimSpace(req.Name),
		APIEndpoint:      strings.TrimSpace(req.APIEndpoint),
		Authorization:    strings.TrimSpace(req.Authorization),
		RequestUserAgent: strings.TrimSpace(req.RequestUserAgent),
		Host:             strings.TrimSpace(req.Host),
		Origin:           strings.TrimSpace(req.Origin),
		Referer:          strings.TrimSpace(req.Referer),
		CustomHeaders:    req.CustomHeaders,
		RefreshInterval:  req.RefreshInterval,
		CacheStrategy:    req.CacheStrategy,
		Enabled:          true,
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
	existing.APIEndpoint = strings.TrimSpace(req.APIEndpoint)
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
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminDeleteUpstream(c *gin.Context) {
	upstreamID := c.Param("id")
	if err := h.state.DeleteUpstream(upstreamID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminRefreshUpstream(c *gin.Context) {
	upstreamID := c.Param("id")
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
	removed, remain := h.state.DedupeCacheVariants(upstreamID)
	c.JSON(http.StatusOK, gin.H{"ok": true, "removed": removed, "remain": remain})
}

func (h *SubscribeHandler) AdminGetSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"global_config": h.state.GetGlobalConfig(),
		"upstreams":     h.state.ListUpstreams(),
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

func (h *SubscribeHandler) AdminListKeys(c *gin.Context) {
	keys := h.state.ListKeys()
	upstreams := h.state.ListUpstreams()
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
	if err := h.state.AddKey(strings.TrimSpace(req.Key), strings.TrimSpace(req.Name), strings.TrimSpace(req.UpstreamID)); err != nil {
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
	if err := h.state.UpdateKey(keyID, strings.TrimSpace(req.Name), req.Enabled, strings.TrimSpace(req.UpstreamID)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminDeleteKey(c *gin.Context) {
	keyID := c.Param("id")
	if err := h.state.DeleteKey(keyID); err != nil {
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

	if raw := c.Query("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			c.JSON(http.StatusOK, gin.H{"logs": h.state.ListLogs(parsed)})
			return
		}
	}

	result := h.state.ListLogsPaginated(page, pageSize)
	c.JSON(http.StatusOK, result)
}

func (h *SubscribeHandler) AdminManualRefresh(c *gin.Context) {
	upstreams := h.state.ListUpstreams()
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

func (h *SubscribeHandler) appendClientLog(keyID, keyToken, keyName, upstreamID, clientIP, userAgent string, uaDetails store.UAMatchDetails, cacheHit bool, status, message string) {
	entry := store.ClientUpdateLog{
		Time:        time.Now(),
		KeyID:       keyID,
		Key:         keyToken,
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

func copyHeaders(src map[string][]string, dst http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
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
