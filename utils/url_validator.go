package utils

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var blockedOutboundPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fc00::/7"),
}

const outboundURLResolveTimeout = 5 * time.Second

func ValidateOutboundURL(rawURL string, allowPrivate bool) error {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return fmt.Errorf("URL不能为空")
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("URL解析失败: %w", err)
	}

	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("URL仅支持http/https协议: %s", parsed.Scheme)
	}

	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return fmt.Errorf("URL缺少主机")
	}

	ctx, cancel := context.WithTimeout(context.Background(), outboundURLResolveTimeout)
	defer cancel()

	resolvedIPs, err := resolveHostIPs(ctx, host)
	if err != nil {
		return fmt.Errorf("解析URL主机失败: %w", err)
	}
	if len(resolvedIPs) == 0 {
		return fmt.Errorf("URL主机未解析到IP地址: %s", host)
	}

	for _, ip := range resolvedIPs {
		if err := validateOutboundIP(ip, allowPrivate); err != nil {
			return fmt.Errorf("URL主机 %s 解析到受限IP %s: %w", host, ip.String(), err)
		}
	}

	return nil
}

func resolveHostIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	resolved := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			continue
		}
		resolved = append(resolved, addr)
	}
	return resolved, nil
}

func validateOutboundIP(ip netip.Addr, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}

	checkIP := ip
	if ip.Is4In6() {
		checkIP = netip.AddrFrom4(ip.As4())
	}

	for _, prefix := range blockedOutboundPrefixes {
		if prefix.Contains(checkIP) {
			return fmt.Errorf("禁止访问内网或保留地址")
		}
	}

	return nil
}
