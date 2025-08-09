package handlers

import (
	"io"
	"jsyproxy/config"
	"jsyproxy/utils"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// SubscribeResponse 上游API响应结构
type SubscribeResponse struct {
	Data struct {
		SubscribeURL string `json:"subscribe_url"`
	} `json:"data"`
}

// SubscribeHandler 订阅处理器
type SubscribeHandler struct {
	config     *config.Config
	httpClient *utils.HTTPClient
}

// NewSubscribeHandler 创建新的订阅处理器
func NewSubscribeHandler(cfg *config.Config) *SubscribeHandler {
	return &SubscribeHandler{
		config:     cfg,
		httpClient: utils.NewHTTPClient(),
	}
}

// GetSubscribe 处理获取订阅的请求
func (h *SubscribeHandler) GetSubscribe(c *gin.Context) {
	// 提取客户端User-Agent，用于后续请求subscribe_url
	clientUserAgent := c.GetHeader("User-Agent")
	log.Printf("客户端User-Agent: %s", clientUserAgent)

	// 准备上游API请求头
	headers := map[string]string{
		"Authorization": h.config.Authorization,
		"User-Agent":    h.config.UserAgent,
		"Host":          h.config.Host,
		"Origin":        h.config.Origin,
		"Referer":       h.config.Referer,
	}

	// 调用上游API
	resp, err := h.httpClient.MakeRequest("GET", h.config.UpstreamURL, headers)
	if err != nil {
		log.Printf("调用上游API失败: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "上游服务不可用",
		})
		return
	}
	defer resp.Body.Close()

	// 检查上游API响应状态
	if resp.StatusCode != http.StatusOK {
		log.Printf("上游API返回错误状态: %d", resp.StatusCode)
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "上游服务返回错误",
		})
		return
	}

	// 解析上游API响应
	var subscribeResp SubscribeResponse
	if err := utils.ParseJSONResponse(resp, &subscribeResp); err != nil {
		log.Printf("解析上游API响应失败: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "解析上游响应失败",
		})
		return
	}

	// 检查subscribe_url是否存在
	if subscribeResp.Data.SubscribeURL == "" {
		log.Printf("上游API响应中缺少subscribe_url")
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "上游响应格式错误",
		})
		return
	}

	// 为subscribe_url请求准备headers，透传客户端User-Agent
	var subscribeHeaders map[string]string
	if clientUserAgent != "" {
		subscribeHeaders = map[string]string{
			"User-Agent": clientUserAgent,
		}
		log.Printf("使用客户端User-Agent请求订阅内容: %s", clientUserAgent)
	} else {
		subscribeHeaders = nil
		log.Printf("客户端未提供User-Agent，使用默认请求")
	}

	// 请求subscribe_url获取实际内容
	contentResp, err := h.httpClient.MakeRequest("GET", subscribeResp.Data.SubscribeURL, subscribeHeaders)
	if err != nil {
		log.Printf("请求subscribe_url失败: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "获取订阅内容失败",
		})
		return
	}
	defer contentResp.Body.Close()

	// 检查内容响应状态
	if contentResp.StatusCode != http.StatusOK {
		log.Printf("subscribe_url返回错误状态: %d", contentResp.StatusCode)
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "订阅内容不可用",
		})
		return
	}

	// 复制响应头
	utils.CopyHeaders(contentResp.Header, c.Writer.Header())

	// 设置状态码
	c.Status(contentResp.StatusCode)

	// 透传响应体
	if _, err := io.Copy(c.Writer, contentResp.Body); err != nil {
		log.Printf("透传响应体失败: %v", err)
		return
	}

	log.Printf("成功处理订阅请求，subscribe_url: %s", subscribeResp.Data.SubscribeURL)
}
