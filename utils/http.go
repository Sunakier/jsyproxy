package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// HTTPClient 封装HTTP客户端
type HTTPClient struct {
	client *http.Client
}

// NewHTTPClient 创建新的HTTP客户端
func NewHTTPClient() *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func NewSafeHTTPClient(allowPrivate bool) *HTTPClient {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("解析连接地址失败: %w", err)
			}

			resolvedIPs, err := resolveHostIPs(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("解析连接主机失败: %w", err)
			}
			if len(resolvedIPs) == 0 {
				return nil, fmt.Errorf("连接主机未解析到IP地址: %s", host)
			}

			var lastErr error
			for _, ip := range resolvedIPs {
				if err := validateOutboundIP(ip, allowPrivate); err != nil {
					return nil, fmt.Errorf("连接主机 %s 解析到受限IP %s: %w", host, ip.String(), err)
				}
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}

			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("连接主机未解析到可用IP地址: %s", host)
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     20,
		IdleConnTimeout:     90 * time.Second,
	}

	return &HTTPClient{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if err := ValidateOutboundURL(req.URL.String(), allowPrivate); err != nil {
					return fmt.Errorf("重定向URL校验失败: %w", err)
				}
				return nil
			},
		},
	}
}

// MakeRequest 发起HTTP请求
func (h *HTTPClient) MakeRequest(method, url string, headers map[string]string) (*http.Response, error) {
	return h.MakeRequestWithContext(context.Background(), method, url, headers)
}

func (h *HTTPClient) MakeRequestWithContext(ctx context.Context, method, url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}

	return resp, nil
}

// ParseJSONResponse 解析JSON响应
func ParseJSONResponse(resp *http.Response, target any) error {
	defer resp.Body.Close()

	body, err := ReadLimited(resp.Body, MaxAPIJSONSize)
	if err != nil {
		return fmt.Errorf("读取响应体失败: %w", err)
	}

	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("解析JSON失败: %w", err)
	}

	return nil
}

const (
	MaxSubscriptionBodySize int64 = 10 << 20  // 10MB
	MaxConfigBodySize       int64 = 1 << 20   // 1MB
	MaxAPIJSONSize          int64 = 512 << 10 // 512KB
)

func ReadLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("响应体超出大小限制 (%d bytes)", limit)
	}
	return data, nil
}

// CopyHeaders 复制HTTP头
func CopyHeaders(src, dst http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
