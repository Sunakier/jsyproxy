package handlers

import (
	"errors"
	"fmt"
	"io"
	"jsyproxy/config"
	"jsyproxy/store"
	"jsyproxy/utils"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

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
	Key  string `json:"key"`
	Name string `json:"name"`
}

type updateSettingsRequest struct {
	UpstreamURL      string `json:"upstream_url"`
	Authorization    string `json:"authorization"`
	RequestUserAgent string `json:"request_user_agent"`
	Host             string `json:"host"`
	Origin           string `json:"origin"`
	Referer          string `json:"referer"`
	RefreshInterval  string `json:"refresh_interval"`
}

type SubscribeHandler struct {
	config     *config.Config
	httpClient *utils.HTTPClient
	state      *store.State
}

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
	go func() {
		if err := h.RefreshCache("startup", ""); err != nil {
			log.Printf("启动预热缓存失败: %v", err)
		}
		for {
			time.Sleep(h.state.GetRefreshInterval())
			if err := h.RefreshCache("timer", ""); err != nil {
				log.Printf("定时刷新缓存失败: %v", err)
			}
		}
	}()
}

func (h *SubscribeHandler) GetSubscribe(c *gin.Context) {
	accessKey := strings.TrimSpace(c.Query("token"))
	if accessKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "缺少token参数"})
		return
	}
	if !h.state.ValidateKey(accessKey) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的token"})
		return
	}

	clientUA := c.GetHeader("User-Agent")
	clientIP := c.ClientIP()

	cache, cacheHit := h.state.GetCache()
	if !cacheHit {
		if err := h.RefreshCache("request-miss", clientUA); err != nil {
			h.appendClientLog(accessKey, clientIP, clientUA, false, "failed", err.Error())
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		cache, cacheHit = h.state.GetCache()
		if !cacheHit {
			h.appendClientLog(accessKey, clientIP, clientUA, false, "failed", "缓存刷新后为空")
			c.JSON(http.StatusBadGateway, gin.H{"error": "订阅内容不可用"})
			return
		}
	}

	copyHeaders(cache.Headers, c.Writer.Header())
	c.Status(cache.StatusCode)
	if _, err := c.Writer.Write(cache.Body); err != nil {
		h.appendClientLog(accessKey, clientIP, clientUA, cacheHit, "failed", "写响应失败")
		return
	}
	h.appendClientLog(accessKey, clientIP, clientUA, cacheHit, "success", "")
}

func (h *SubscribeHandler) RefreshCache(reason string, downstreamUA string) error {
	cfg := h.state.GetConfig()
	if strings.TrimSpace(cfg.UpstreamURL) == "" {
		return errors.New("请先在管理台配置 upstream_url")
	}

	headers := map[string]string{}
	if cfg.Authorization != "" {
		headers["Authorization"] = cfg.Authorization
	}
	if cfg.RequestUserAgent != "" {
		headers["User-Agent"] = cfg.RequestUserAgent
	}
	if cfg.Host != "" {
		headers["Host"] = cfg.Host
	}
	if cfg.Origin != "" {
		headers["Origin"] = cfg.Origin
	}
	if cfg.Referer != "" {
		headers["Referer"] = cfg.Referer
	}

	resp, err := h.httpClient.MakeRequest(http.MethodGet, cfg.UpstreamURL, headers)
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

	if downstreamUA == "" {
		downstreamUA = cfg.RequestUserAgent
	}
	contentHeaders := map[string]string{}
	if downstreamUA != "" {
		contentHeaders["User-Agent"] = downstreamUA
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

	h.state.SetCache(&store.CachedSubscription{
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

	log.Printf("订阅缓存刷新成功 reason=%s source=%s bytes=%d", reason, subscribeResp.Data.SubscribeURL, len(body))
	return nil
}

func (h *SubscribeHandler) AdminPage(c *gin.Context) {
	c.File("./static/admin.html")
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
	cache, hasCache := h.state.GetCache()
	cfg := h.state.GetConfig()

	updatedAt := ""
	traffic := gin.H{}
	if hasCache {
		used := cache.TrafficStatus.UsedUpload + cache.TrafficStatus.UsedDownload
		traffic = gin.H{
			"plan_name":        cache.TrafficStatus.PlanName,
			"expired_at":       cache.TrafficStatus.ExpiredAt,
			"reset_day":        cache.TrafficStatus.ResetDay,
			"used_upload":      cache.TrafficStatus.UsedUpload,
			"used_download":    cache.TrafficStatus.UsedDownload,
			"used_total":       used,
			"transfer_enable":  cache.TrafficStatus.TransferEnable,
			"usage_text":       fmt.Sprintf("%s / %s", formatBytes(used), formatBytes(cache.TrafficStatus.TransferEnable)),
			"expiry_text":      formatExpiry(cache.TrafficStatus.ExpiredAt, cache.TrafficStatus.ResetDay),
			"subscribe_source": cache.SourceURL,
		}
		updatedAt = cache.UpdatedAt.Format(time.RFC3339)
	}

	c.JSON(http.StatusOK, gin.H{
		"has_cache":           hasCache,
		"cache_updated_at":    updatedAt,
		"refresh_interval":    cfg.RefreshInterval,
		"key_count":           len(h.state.ListKeys()),
		"log_count":           h.state.LogCount(),
		"traffic":             traffic,
		"upstream_configured": cfg.UpstreamURL != "",
	})
}

func (h *SubscribeHandler) AdminGetSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"settings": h.state.GetConfig()})
}

func (h *SubscribeHandler) AdminUpdateSettings(c *gin.Context) {
	var req updateSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	interval := strings.TrimSpace(req.RefreshInterval)
	if interval == "" {
		interval = "10m"
	}
	if _, err := time.ParseDuration(normalizeDurationInput(interval)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "refresh_interval格式错误，示例: 10m / 5m / 125s"})
		return
	}
	next := store.UpstreamConfig{
		UpstreamURL:      strings.TrimSpace(req.UpstreamURL),
		Authorization:    strings.TrimSpace(req.Authorization),
		RequestUserAgent: strings.TrimSpace(req.RequestUserAgent),
		Host:             strings.TrimSpace(req.Host),
		Origin:           strings.TrimSpace(req.Origin),
		Referer:          strings.TrimSpace(req.Referer),
		RefreshInterval:  normalizeDurationInput(interval),
	}
	if err := h.state.UpdateConfig(next); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存配置失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminListKeys(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"keys": h.state.ListKeys()})
}

func (h *SubscribeHandler) AdminAddKey(c *gin.Context) {
	var req addKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	if err := h.state.AddKey(strings.TrimSpace(req.Key), strings.TrimSpace(req.Name)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminDeleteKey(c *gin.Context) {
	if err := h.state.DeleteKey(strings.TrimSpace(c.Param("key"))); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) AdminGetLogs(c *gin.Context) {
	limit := 100
	if raw := c.Query("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	c.JSON(http.StatusOK, gin.H{"logs": h.state.ListLogs(limit)})
}

func (h *SubscribeHandler) AdminManualRefresh(c *gin.Context) {
	if err := h.RefreshCache("manual", ""); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SubscribeHandler) appendClientLog(key, clientIP, userAgent string, cacheHit bool, status, message string) {
	entry := store.ClientUpdateLog{
		Time:      time.Now(),
		Key:       key,
		ClientIP:  clientIP,
		UserAgent: userAgent,
		CacheHit:  cacheHit,
		Status:    status,
		Message:   message,
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

func normalizeDurationInput(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "10m"
	}
	if _, err := strconv.Atoi(trimmed); err == nil {
		return trimmed + "s"
	}
	return trimmed
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
	if expiredAt <= 0 {
		if resetDay > 0 {
			return fmt.Sprintf("下次重置日: 每月%d号", resetDay)
		}
		return "未提供到期信息"
	}
	t := time.Unix(expiredAt, 0)
	if resetDay > 0 {
		return fmt.Sprintf("到期: %s / 下次重置日: 每月%d号", t.Format("2006-01-02 15:04:05"), resetDay)
	}
	return "到期: " + t.Format("2006-01-02 15:04:05")
}
