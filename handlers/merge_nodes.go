package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"jsyproxy/store"

	"gopkg.in/yaml.v3"
)

type MergedNode struct {
	Protocol string
	Name     string
	Host     string
	Port     int
	render   func(name string) (string, error)
}

type ClashRenderOptions struct {
	AdditionalRules []string
}

func ParseSubscriptionNodes(body []byte) ([]MergedNode, error) {
	lines, err := extractSubscriptionLines(body)
	if err != nil {
		return nil, err
	}
	result := make([]MergedNode, 0, len(lines))
	for _, line := range lines {
		node, err := parseNodeLine(line)
		if err != nil {
			continue
		}
		if strings.TrimSpace(node.Name) == "" {
			node.Name = strings.ToUpper(node.Protocol) + "|" + node.Host
		}
		result = append(result, node)
	}
	if len(result) == 0 {
		return nil, errors.New("未解析到可用节点")
	}
	return result, nil
}

func ApplyNameReplacements(nodes []MergedNode, replacements []store.MergeNameReplacement) []MergedNode {
	type compiledReplacement struct {
		literal string
		re      *regexp.Regexp
		to      string
	}
	compiled := make([]compiledReplacement, 0, len(replacements))
	for _, item := range replacements {
		from := strings.TrimSpace(item.From)
		if from == "" {
			continue
		}
		if pattern, ok := unwrapRegexPattern(from); ok {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			compiled = append(compiled, compiledReplacement{re: re, to: item.To})
			continue
		}
		compiled = append(compiled, compiledReplacement{literal: from, to: item.To})
	}
	if len(compiled) == 0 {
		return nodes
	}
	for idx := range nodes {
		for _, item := range compiled {
			if item.re != nil {
				nodes[idx].Name = item.re.ReplaceAllString(nodes[idx].Name, item.to)
				continue
			}
			nodes[idx].Name = strings.ReplaceAll(nodes[idx].Name, item.literal, item.to)
		}
	}
	return nodes
}

func DedupeMergedNodes(nodes []MergedNode) []MergedNode {
	seen := make(map[string]struct{}, len(nodes))
	result := make([]MergedNode, 0, len(nodes))
	for _, node := range nodes {
		name := strings.TrimSpace(strings.ToLower(node.Name))
		key := strings.ToLower(strings.TrimSpace(node.Protocol)) + "|" + strings.TrimSpace(node.Host) + "|" + strconv.Itoa(node.Port) + "|" + name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, node)
	}
	return result
}

func SortMergedNodesByName(nodes []MergedNode) []MergedNode {
	if len(nodes) <= 1 {
		return nodes
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		left := strings.ToLower(strings.TrimSpace(nodes[i].Name))
		right := strings.ToLower(strings.TrimSpace(nodes[j].Name))
		if left == right {
			return strings.ToLower(nodes[i].Protocol) < strings.ToLower(nodes[j].Protocol)
		}
		return left < right
	})
	return nodes
}

func ApplyProtocolEmoji(nodes []MergedNode) []MergedNode {
	emojiByProtocol := map[string]string{
		"vmess":     "🔷",
		"vless":     "🟪",
		"trojan":    "🐴",
		"ss":        "🟢",
		"ssr":       "🟠",
		"hysteria":  "🌪️",
		"hysteria2": "⚡",
		"tuic":      "🚀",
		"wireguard": "🛡️",
		"socks5":    "🧦",
		"http":      "🌐",
	}
	for i := range nodes {
		name := strings.TrimSpace(nodes[i].Name)
		if name == "" {
			continue
		}
		emoji := emojiByProtocol[strings.ToLower(strings.TrimSpace(nodes[i].Protocol))]
		if emoji == "" {
			continue
		}
		if strings.HasPrefix(name, emoji+" ") {
			continue
		}
		nodes[i].Name = emoji + " " + name
	}
	return nodes
}

func FilterNodes(nodes []MergedNode, includes, excludes []string, rules []store.MergeRule) []MergedNode {
	result := make([]MergedNode, 0, len(nodes))
	for _, node := range nodes {
		if !matchNameIncludes(node.Name, includes) {
			continue
		}
		if matchNameExcludes(node.Name, excludes) {
			continue
		}
		if !matchRules(node, rules) {
			continue
		}
		result = append(result, node)
	}
	return result
}

func RenderStandardV2RaySubscription(nodes []MergedNode) ([]byte, error) {
	lines := make([]string, 0, len(nodes))
	for _, node := range nodes {
		line, err := node.render(node.Name)
		if err != nil {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil, errors.New("合成订阅失败：没有可输出节点")
	}
	text := strings.Join(lines, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(text))
	return []byte(encoded), nil
}

func RenderClashSubscription(nodes []MergedNode, upstreamRaw []byte, clashCfg store.ClashConfig, opts ...ClashRenderOptions) ([]byte, error) {
	proxies := make([]map[string]interface{}, 0, len(nodes))
	proxyNames := make([]string, 0, len(nodes))
	for _, node := range nodes {
		line, err := node.render(node.Name)
		if err != nil {
			continue
		}
		proxy, err := uriToClashProxy(line)
		if err != nil {
			continue
		}
		proxies = append(proxies, proxy)
		proxyNames = append(proxyNames, asString(proxy["name"]))
	}
	if len(proxies) == 0 {
		return nil, errors.New("合成Clash订阅失败：没有可输出节点")
	}

	root := buildClashRootTemplate(upstreamRaw, clashCfg)
	root["proxies"] = proxies
	if !injectProxyNamesIntoGroups(root, proxyNames) {
		root["proxy-groups"] = defaultClashProxyGroups(proxyNames)
	}
	additionalRules := []string{}
	if len(opts) > 0 {
		additionalRules = append(additionalRules, opts[0].AdditionalRules...)
	}
	ensureClashRules(root, additionalRules)

	out, err := yaml.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("生成Clash YAML失败: %w", err)
	}
	return out, nil
}

func RenderSingBoxSubscription(nodes []MergedNode, upstreamRaw []byte) ([]byte, error) {
	outbounds := make([]map[string]interface{}, 0, len(nodes))
	tags := make([]string, 0, len(nodes))
	for _, node := range nodes {
		line, err := node.render(node.Name)
		if err != nil {
			continue
		}
		outbound, err := uriToSingBoxOutbound(line)
		if err != nil {
			continue
		}
		tag := asString(outbound["tag"])
		if tag != "" {
			tags = append(tags, tag)
		}
		outbounds = append(outbounds, outbound)
	}
	if len(outbounds) == 0 {
		return nil, errors.New("合成Sing-box订阅失败：没有可输出节点")
	}

	root := buildSingBoxRootTemplate(upstreamRaw)
	normalizedTags := dedupeStrings(tags)
	selector := map[string]interface{}{
		"type":      "selector",
		"tag":       "proxy",
		"outbounds": normalizedTags,
	}
	finalOutbounds := make([]interface{}, 0, len(outbounds)+3)
	finalOutbounds = append(finalOutbounds, selector)
	for _, item := range outbounds {
		finalOutbounds = append(finalOutbounds, item)
	}
	finalOutbounds = append(finalOutbounds,
		map[string]interface{}{"type": "direct", "tag": "direct"},
		map[string]interface{}{"type": "block", "tag": "block"},
	)
	root["outbounds"] = finalOutbounds
	ensureSingBoxRoute(root)

	buf, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("生成Sing-box JSON失败: %w", err)
	}
	return buf, nil
}

func RenderSurgeSubscription(nodes []MergedNode) ([]byte, error) {
	proxyLines := make([]string, 0, len(nodes))
	names := make([]string, 0, len(nodes))
	for _, node := range nodes {
		line, err := node.render(node.Name)
		if err != nil {
			continue
		}
		name, proxyLine, err := uriToSurgeProxy(line)
		if err != nil {
			continue
		}
		if strings.TrimSpace(name) == "" || strings.TrimSpace(proxyLine) == "" {
			continue
		}
		names = append(names, name)
		proxyLines = append(proxyLines, proxyLine)
	}
	if len(proxyLines) == 0 {
		return nil, errors.New("合成Surge订阅失败：没有可输出节点")
	}
	names = dedupeStrings(names)
	buf := strings.Builder{}
	buf.WriteString("[General]\n")
	buf.WriteString("skip-proxy = 127.0.0.1, localhost\n")
	buf.WriteString("\n[Proxy]\n")
	buf.WriteString(strings.Join(proxyLines, "\n"))
	buf.WriteString("\n\n[Proxy Group]\n")
	groupProxies := append([]string{"DIRECT"}, names...)
	buf.WriteString("PROXY = select, " + strings.Join(groupProxies, ", ") + "\n")
	buf.WriteString("\n[Rule]\n")
	buf.WriteString("FINAL,PROXY\n")
	return []byte(buf.String()), nil
}

func uriToSurgeProxy(line string) (string, string, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", "", errors.New("empty")
	}
	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasPrefix(lower, "ss://"):
		return ssURIToSurgeProxy(trimmed)
	case strings.HasPrefix(lower, "ssr://"):
		converted, err := ssrURIToSSURI(trimmed)
		if err != nil {
			return "", "", err
		}
		return ssURIToSurgeProxy(converted)
	case strings.HasPrefix(lower, "socks5://") || strings.HasPrefix(lower, "socks://"):
		return socks5URIToSurgeProxy(trimmed)
	case strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://"):
		return httpURIToSurgeProxy(trimmed)
	case strings.HasPrefix(lower, "trojan://"):
		return trojanURIToSurgeProxy(trimmed)
	case strings.HasPrefix(lower, "vmess://"):
		return vmessURIToSurgeProxy(trimmed)
	case strings.HasPrefix(lower, "vless://"):
		return vlessURIToSurgeProxy(trimmed)
	default:
		return "", "", errors.New("unsupported surge protocol")
	}
}

func socks5URIToSurgeProxy(line string) (string, string, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return "", "", err
	}
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "socks5"
	}
	server := u.Hostname()
	port := parsePort(u.Port())
	if server == "" || port <= 0 {
		return "", "", errors.New("invalid socks5")
	}
	lineOut := fmt.Sprintf("%s = socks5, %s, %d", sanitizeSurgeName(name), server, port)
	if u.User != nil {
		username := strings.TrimSpace(u.User.Username())
		password, _ := u.User.Password()
		if username != "" {
			lineOut += ", username=" + username
		}
		if password != "" {
			lineOut += ", password=" + password
		}
	}
	return sanitizeSurgeName(name), lineOut, nil
}

func httpURIToSurgeProxy(line string) (string, string, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return "", "", err
	}
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "http"
	}
	server := u.Hostname()
	port := parsePort(u.Port())
	if server == "" || port <= 0 {
		return "", "", errors.New("invalid http")
	}
	lineOut := fmt.Sprintf("%s = http, %s, %d", sanitizeSurgeName(name), server, port)
	if u.User != nil {
		username := strings.TrimSpace(u.User.Username())
		password, _ := u.User.Password()
		if username != "" {
			lineOut += ", username=" + username
		}
		if password != "" {
			lineOut += ", password=" + password
		}
	}
	if strings.EqualFold(u.Scheme, "https") {
		lineOut += ", tls=true"
	}
	return sanitizeSurgeName(name), lineOut, nil
}

func ssURIToSurgeProxy(line string) (string, string, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return "", "", err
	}
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "ss"
	}
	method := ""
	password := ""
	if u.User != nil {
		method = u.User.Username()
		password, _ = u.User.Password()
	}
	if password == "" || strings.Contains(method, "=") {
		payload := strings.TrimPrefix(core, "ss://")
		if idx := strings.Index(payload, "@"); idx >= 0 {
			userinfo := payload[:idx]
			if decoded, err := decodeBase64Loose(userinfo); err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					method = strings.TrimSpace(parts[0])
					password = strings.TrimSpace(parts[1])
				}
			}
		}
	}
	server := u.Hostname()
	port := parsePort(u.Port())
	if server == "" || port <= 0 || method == "" || password == "" {
		return "", "", errors.New("invalid ss")
	}
	lineOut := fmt.Sprintf("%s = ss, %s, %d, encrypt-method=%s, password=%s, udp-relay=true", sanitizeSurgeName(name), server, port, method, password)
	return sanitizeSurgeName(name), lineOut, nil
}

func trojanURIToSurgeProxy(line string) (string, string, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return "", "", err
	}
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "trojan"
	}
	password, _ := u.User.Password()
	if password == "" {
		password = u.User.Username()
	}
	server := u.Hostname()
	port := parsePort(u.Port())
	if server == "" || port <= 0 || password == "" {
		return "", "", errors.New("invalid trojan")
	}
	q := u.Query()
	sni := strings.TrimSpace(q.Get("sni"))
	lineOut := fmt.Sprintf("%s = trojan, %s, %d, password=%s", sanitizeSurgeName(name), server, port, password)
	if sni != "" {
		lineOut += ", sni=" + sni
	}
	return sanitizeSurgeName(name), lineOut, nil
}

func vmessURIToSurgeProxy(line string) (string, string, error) {
	core, _ := splitCoreAndFragment(line)
	payload := strings.TrimPrefix(core, "vmess://")
	decoded, err := decodeBase64Loose(payload)
	if err != nil {
		return "", "", err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		return "", "", err
	}
	name := fallbackString(asString(cfg["ps"]), "vmess")
	server := fallbackString(asString(cfg["add"]), asString(cfg["host"]))
	port := parsePort(asString(cfg["port"]))
	uuid := asString(cfg["id"])
	if server == "" || port <= 0 || uuid == "" {
		return "", "", errors.New("invalid vmess")
	}
	lineOut := fmt.Sprintf("%s = vmess, %s, %d, username=%s, ws=false, tls=%t", sanitizeSurgeName(name), server, port, uuid, strings.EqualFold(asString(cfg["tls"]), "tls") || strings.EqualFold(asString(cfg["tls"]), "true"))
	return sanitizeSurgeName(name), lineOut, nil
}

func vlessURIToSurgeProxy(line string) (string, string, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return "", "", err
	}
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "vless"
	}
	server := u.Hostname()
	port := parsePort(u.Port())
	uuid := strings.TrimSpace(u.User.Username())
	if server == "" || port <= 0 || uuid == "" {
		return "", "", errors.New("invalid vless")
	}
	q := u.Query()
	lineOut := fmt.Sprintf("%s = vless, %s, %d, username=%s, tls=%t", sanitizeSurgeName(name), server, port, uuid, strings.EqualFold(q.Get("security"), "tls"))
	if sni := strings.TrimSpace(q.Get("sni")); sni != "" {
		lineOut += ", sni=" + sni
	}
	return sanitizeSurgeName(name), lineOut, nil
}

func sanitizeSurgeName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "proxy"
	}
	cleaned := strings.ReplaceAll(trimmed, ",", "_")
	cleaned = strings.ReplaceAll(cleaned, "=", "_")
	cleaned = strings.ReplaceAll(cleaned, "\n", " ")
	cleaned = strings.ReplaceAll(cleaned, "\r", " ")
	return cleaned
}

func buildSingBoxRootTemplate(upstreamRaw []byte) map[string]interface{} {
	if m := parseJSONMap(upstreamRaw); m != nil {
		if _, ok := m["outbounds"]; ok {
			return m
		}
	}
	return defaultSingBoxRootTemplate()
}

func defaultSingBoxRootTemplate() map[string]interface{} {
	return map[string]interface{}{
		"log": map[string]interface{}{
			"level": "info",
		},
		"dns": map[string]interface{}{
			"servers": []interface{}{
				map[string]interface{}{"tag": "dns_remote", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
				map[string]interface{}{"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"},
			},
		},
		"route": map[string]interface{}{},
	}
}

func ensureSingBoxRoute(root map[string]interface{}) {
	route, ok := root["route"].(map[string]interface{})
	if !ok {
		route = map[string]interface{}{}
		root["route"] = route
	}
	rules, ok := route["rules"].([]interface{})
	if ok && len(rules) > 0 {
		return
	}
	route["rules"] = []interface{}{
		map[string]interface{}{"protocol": "dns", "outbound": "direct"},
		map[string]interface{}{"network": "udp", "port": 443, "outbound": "block"},
		map[string]interface{}{"outbound": "proxy"},
	}
}

func parseJSONMap(raw []byte) map[string]interface{} {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	if m == nil {
		return nil
	}
	return m
}

func uriToSingBoxOutbound(line string) (map[string]interface{}, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil, errors.New("empty node")
	}
	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasPrefix(lower, "vmess://"):
		return vmessURIToSingBoxOutbound(trimmed)
	case strings.HasPrefix(lower, "vless://"):
		return vlessURIToSingBoxOutbound(trimmed)
	case strings.HasPrefix(lower, "trojan://"):
		return trojanURIToSingBoxOutbound(trimmed)
	case strings.HasPrefix(lower, "ss://"):
		return ssURIToSingBoxOutbound(trimmed)
	case strings.HasPrefix(lower, "ssr://"):
		converted, err := ssrURIToSSURI(trimmed)
		if err != nil {
			return nil, err
		}
		return ssURIToSingBoxOutbound(converted)
	case strings.HasPrefix(lower, "socks5://") || strings.HasPrefix(lower, "socks://"):
		return socks5URIToSingBoxOutbound(trimmed)
	case strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://"):
		return httpURIToSingBoxOutbound(trimmed)
	case strings.HasPrefix(lower, "wireguard://") || strings.HasPrefix(lower, "wg://"):
		return wireguardURIToSingBoxOutbound(trimmed)
	case strings.HasPrefix(lower, "hysteria://") || strings.HasPrefix(lower, "hy://"):
		return hysteriaURIToSingBoxOutbound(trimmed)
	case strings.HasPrefix(lower, "hysteria2://") || strings.HasPrefix(lower, "hy2://"):
		return hysteria2URIToSingBoxOutbound(trimmed)
	case strings.HasPrefix(lower, "tuic://"):
		return tuicURIToSingBoxOutbound(trimmed)
	default:
		return nil, errors.New("unsupported singbox protocol")
	}
}

func vmessURIToSingBoxOutbound(line string) (map[string]interface{}, error) {
	core, _ := splitCoreAndFragment(line)
	payload := strings.TrimPrefix(core, "vmess://")
	decoded, err := decodeBase64Loose(payload)
	if err != nil {
		return nil, err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		return nil, err
	}
	tag := fallbackString(asString(cfg["ps"]), "vmess")
	outbound := map[string]interface{}{
		"type":        "vmess",
		"tag":         tag,
		"server":      fallbackString(asString(cfg["add"]), asString(cfg["host"])),
		"server_port": parsePort(asString(cfg["port"])),
		"uuid":        asString(cfg["id"]),
		"security":    fallbackString(asString(cfg["scy"]), "auto"),
	}
	if network := asString(cfg["net"]); network != "" {
		outbound["network"] = network
		switch strings.ToLower(network) {
		case "ws":
			transport := map[string]interface{}{"type": "ws"}
			if path := asString(cfg["path"]); path != "" {
				transport["path"] = path
			}
			if host := asString(cfg["host"]); host != "" {
				transport["headers"] = map[string]interface{}{"Host": host}
			}
			outbound["transport"] = transport
		case "grpc":
			serviceName := asString(cfg["path"])
			if serviceName == "" {
				serviceName = asString(cfg["serviceName"])
			}
			transport := map[string]interface{}{"type": "grpc"}
			if serviceName != "" {
				transport["service_name"] = serviceName
			}
			outbound["transport"] = transport
		}
	}
	if tls := strings.ToLower(asString(cfg["tls"])); tls == "tls" || tls == "true" {
		tlsMap := map[string]interface{}{"enabled": true}
		if sni := asString(cfg["sni"]); sni != "" {
			tlsMap["server_name"] = sni
		} else if host := asString(cfg["host"]); host != "" {
			tlsMap["server_name"] = host
		}
		if fp := asString(cfg["fp"]); fp != "" {
			tlsMap["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fp}
		}
		outbound["tls"] = tlsMap
	}
	if asString(outbound["server"]) == "" || asInt(outbound["server_port"]) <= 0 || asString(outbound["uuid"]) == "" {
		return nil, errors.New("invalid vmess")
	}
	return outbound, nil
}

func vlessURIToSingBoxOutbound(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	tag, _ := url.QueryUnescape(fragment)
	if tag == "" {
		tag = "vless"
	}
	outbound := map[string]interface{}{
		"type":        "vless",
		"tag":         tag,
		"server":      u.Hostname(),
		"server_port": parsePort(u.Port()),
		"uuid":        strings.TrimSpace(u.User.Username()),
	}
	if network := q.Get("type"); network != "" {
		outbound["network"] = network
		switch strings.ToLower(network) {
		case "ws":
			transport := map[string]interface{}{"type": "ws"}
			if path := strings.TrimSpace(q.Get("path")); path != "" {
				transport["path"] = path
			}
			if host := strings.TrimSpace(q.Get("host")); host != "" {
				transport["headers"] = map[string]interface{}{"Host": host}
			}
			outbound["transport"] = transport
		case "grpc":
			transport := map[string]interface{}{"type": "grpc"}
			if serviceName := firstNonEmpty(strings.TrimSpace(q.Get("serviceName")), strings.TrimSpace(q.Get("service_name"))); serviceName != "" {
				transport["service_name"] = serviceName
			}
			outbound["transport"] = transport
		case "httpupgrade":
			transport := map[string]interface{}{"type": "httpupgrade"}
			if path := strings.TrimSpace(q.Get("path")); path != "" {
				transport["path"] = path
			}
			outbound["transport"] = transport
		}
	}
	security := strings.ToLower(strings.TrimSpace(q.Get("security")))
	if security == "tls" || security == "reality" {
		tlsMap := map[string]interface{}{"enabled": true}
		if sni := strings.TrimSpace(q.Get("sni")); sni != "" {
			tlsMap["server_name"] = sni
		}
		if fp := strings.TrimSpace(q.Get("fp")); fp != "" {
			tlsMap["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fp}
		}
		if parseBoolString(q.Get("allowInsecure")) {
			tlsMap["insecure"] = true
		}
		if security == "reality" {
			reality := map[string]interface{}{}
			if pbk := strings.TrimSpace(q.Get("pbk")); pbk != "" {
				reality["public_key"] = pbk
			}
			if sid := strings.TrimSpace(q.Get("sid")); sid != "" {
				reality["short_id"] = sid
			}
			if spider := strings.TrimSpace(q.Get("spx")); spider != "" {
				reality["spider_x"] = spider
			}
			if len(reality) > 0 {
				tlsMap["reality"] = reality
			}
		}
		outbound["tls"] = tlsMap
	}
	if flow := strings.TrimSpace(q.Get("flow")); flow != "" {
		outbound["flow"] = flow
	}
	if asString(outbound["server"]) == "" || asInt(outbound["server_port"]) <= 0 || asString(outbound["uuid"]) == "" {
		return nil, errors.New("invalid vless")
	}
	return outbound, nil
}

func trojanURIToSingBoxOutbound(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	tag, _ := url.QueryUnescape(fragment)
	if tag == "" {
		tag = "trojan"
	}
	password, _ := u.User.Password()
	if password == "" {
		password = u.User.Username()
	}
	outbound := map[string]interface{}{
		"type":        "trojan",
		"tag":         tag,
		"server":      u.Hostname(),
		"server_port": parsePort(u.Port()),
		"password":    password,
	}
	if sni := q.Get("sni"); sni != "" {
		tlsMap := map[string]interface{}{"enabled": true, "server_name": sni}
		if fp := strings.TrimSpace(q.Get("fp")); fp != "" {
			tlsMap["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fp}
		}
		if parseBoolString(q.Get("allowInsecure")) {
			tlsMap["insecure"] = true
		}
		outbound["tls"] = tlsMap
	}
	if network := strings.ToLower(strings.TrimSpace(q.Get("type"))); network != "" {
		outbound["network"] = network
		switch network {
		case "ws":
			transport := map[string]interface{}{"type": "ws"}
			if path := strings.TrimSpace(q.Get("path")); path != "" {
				transport["path"] = path
			}
			if host := strings.TrimSpace(q.Get("host")); host != "" {
				transport["headers"] = map[string]interface{}{"Host": host}
			}
			outbound["transport"] = transport
		case "grpc":
			transport := map[string]interface{}{"type": "grpc"}
			if serviceName := firstNonEmpty(strings.TrimSpace(q.Get("serviceName")), strings.TrimSpace(q.Get("service_name"))); serviceName != "" {
				transport["service_name"] = serviceName
			}
			outbound["transport"] = transport
		}
	}
	if asString(outbound["server"]) == "" || asInt(outbound["server_port"]) <= 0 || asString(outbound["password"]) == "" {
		return nil, errors.New("invalid trojan")
	}
	return outbound, nil
}

func ssURIToSingBoxOutbound(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	tag, _ := url.QueryUnescape(fragment)
	if tag == "" {
		tag = "ss"
	}
	method := ""
	password := ""
	if u.User != nil {
		method = u.User.Username()
		password, _ = u.User.Password()
	}
	if password == "" || strings.Contains(method, "=") {
		payload := strings.TrimPrefix(core, "ss://")
		if idx := strings.Index(payload, "@"); idx >= 0 {
			userinfo := payload[:idx]
			if decoded, err := decodeBase64Loose(userinfo); err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					method = strings.TrimSpace(parts[0])
					password = strings.TrimSpace(parts[1])
				}
			}
		}
	}
	outbound := map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         tag,
		"server":      u.Hostname(),
		"server_port": parsePort(u.Port()),
		"method":      method,
		"password":    password,
	}
	if asString(outbound["server"]) == "" || asInt(outbound["server_port"]) <= 0 || asString(outbound["method"]) == "" || asString(outbound["password"]) == "" {
		return nil, errors.New("invalid ss")
	}
	return outbound, nil
}

func socks5URIToSingBoxOutbound(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	tag, _ := url.QueryUnescape(fragment)
	if tag == "" {
		tag = "socks5"
	}
	outbound := map[string]interface{}{
		"type":        "socks",
		"tag":         tag,
		"server":      u.Hostname(),
		"server_port": parsePort(u.Port()),
	}
	if u.User != nil {
		if username := strings.TrimSpace(u.User.Username()); username != "" {
			outbound["username"] = username
		}
		if password, _ := u.User.Password(); strings.TrimSpace(password) != "" {
			outbound["password"] = password
		}
	}
	if asString(outbound["server"]) == "" || asInt(outbound["server_port"]) <= 0 {
		return nil, errors.New("invalid socks5")
	}
	return outbound, nil
}

func httpURIToSingBoxOutbound(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	tag, _ := url.QueryUnescape(fragment)
	if tag == "" {
		tag = "http"
	}
	outbound := map[string]interface{}{
		"type":        "http",
		"tag":         tag,
		"server":      u.Hostname(),
		"server_port": parsePort(u.Port()),
	}
	if u.User != nil {
		if username := strings.TrimSpace(u.User.Username()); username != "" {
			outbound["username"] = username
		}
		if password, _ := u.User.Password(); strings.TrimSpace(password) != "" {
			outbound["password"] = password
		}
	}
	if strings.EqualFold(u.Scheme, "https") {
		outbound["tls"] = map[string]interface{}{"enabled": true, "server_name": u.Hostname()}
	}
	if asString(outbound["server"]) == "" || asInt(outbound["server_port"]) <= 0 {
		return nil, errors.New("invalid http")
	}
	return outbound, nil
}

func wireguardURIToSingBoxOutbound(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	tag, _ := url.QueryUnescape(fragment)
	if tag == "" {
		tag = "wireguard"
	}
	peerPublicKey := strings.TrimSpace(q.Get("publickey"))
	if peerPublicKey == "" {
		peerPublicKey = strings.TrimSpace(q.Get("peer_public_key"))
	}
	privateKey := strings.TrimSpace(q.Get("privatekey"))
	if privateKey == "" {
		privateKey = strings.TrimSpace(q.Get("private_key"))
	}
	outbound := map[string]interface{}{
		"type":            "wireguard",
		"tag":             tag,
		"server":          u.Hostname(),
		"server_port":     parsePort(u.Port()),
		"private_key":     privateKey,
		"peer_public_key": peerPublicKey,
	}
	if address := strings.TrimSpace(q.Get("address")); address != "" {
		outbound["local_address"] = strings.Split(address, ",")
	}
	if reserved := strings.TrimSpace(q.Get("reserved")); reserved != "" {
		outbound["reserved"] = strings.Split(reserved, ",")
	}
	if mtu := parsePort(q.Get("mtu")); mtu > 0 {
		outbound["mtu"] = mtu
	}
	if asString(outbound["server"]) == "" || asInt(outbound["server_port"]) <= 0 || asString(outbound["private_key"]) == "" || asString(outbound["peer_public_key"]) == "" {
		return nil, errors.New("invalid wireguard")
	}
	return outbound, nil
}

func hysteriaURIToSingBoxOutbound(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	tag, _ := url.QueryUnescape(fragment)
	if tag == "" {
		tag = "hysteria"
	}
	auth := strings.TrimSpace(q.Get("auth"))
	if auth == "" {
		auth = strings.TrimSpace(q.Get("auth_str"))
	}
	outbound := map[string]interface{}{
		"type":        "hysteria",
		"tag":         tag,
		"server":      u.Hostname(),
		"server_port": parsePort(u.Port()),
	}
	if auth != "" {
		outbound["auth_str"] = auth
	}
	if upMbps := parsePort(q.Get("upmbps")); upMbps > 0 {
		outbound["up_mbps"] = upMbps
	}
	if downMbps := parsePort(q.Get("downmbps")); downMbps > 0 {
		outbound["down_mbps"] = downMbps
	}
	if obfs := strings.TrimSpace(q.Get("obfs")); obfs != "" {
		outbound["obfs"] = obfs
	}
	if sni := q.Get("sni"); sni != "" {
		outbound["tls"] = map[string]interface{}{"enabled": true, "server_name": sni}
	}
	if asString(outbound["server"]) == "" || asInt(outbound["server_port"]) <= 0 {
		return nil, errors.New("invalid hysteria")
	}
	return outbound, nil
}

func hysteria2URIToSingBoxOutbound(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	tag, _ := url.QueryUnescape(fragment)
	if tag == "" {
		tag = "hysteria2"
	}
	password, _ := u.User.Password()
	if password == "" {
		password = u.User.Username()
	}
	outbound := map[string]interface{}{
		"type":        "hysteria2",
		"tag":         tag,
		"server":      u.Hostname(),
		"server_port": parsePort(u.Port()),
		"password":    password,
	}
	if sni := q.Get("sni"); sni != "" {
		tlsMap := map[string]interface{}{"enabled": true, "server_name": sni}
		if parseBoolString(q.Get("insecure")) || parseBoolString(q.Get("allowInsecure")) {
			tlsMap["insecure"] = true
		}
		if alpn := splitCSV(q.Get("alpn")); len(alpn) > 0 {
			tlsMap["alpn"] = alpn
		}
		outbound["tls"] = tlsMap
	}
	if obfs := strings.TrimSpace(q.Get("obfs")); obfs != "" {
		obfsMap := map[string]interface{}{"type": obfs}
		if pwd := firstNonEmpty(strings.TrimSpace(q.Get("obfs-password")), strings.TrimSpace(q.Get("obfs_password"))); pwd != "" {
			obfsMap["password"] = pwd
		}
		outbound["obfs"] = obfsMap
	}
	if asString(outbound["server"]) == "" || asInt(outbound["server_port"]) <= 0 || asString(outbound["password"]) == "" {
		return nil, errors.New("invalid hysteria2")
	}
	return outbound, nil
}

func tuicURIToSingBoxOutbound(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	tag, _ := url.QueryUnescape(fragment)
	if tag == "" {
		tag = "tuic"
	}
	password, _ := u.User.Password()
	outbound := map[string]interface{}{
		"type":        "tuic",
		"tag":         tag,
		"server":      u.Hostname(),
		"server_port": parsePort(u.Port()),
		"uuid":        u.User.Username(),
		"password":    password,
	}
	q := u.Query()
	if sni := strings.TrimSpace(q.Get("sni")); sni != "" {
		outbound["tls"] = map[string]interface{}{"enabled": true, "server_name": sni}
	}
	if alpn := splitCSV(q.Get("alpn")); len(alpn) > 0 {
		if tls, ok := outbound["tls"].(map[string]interface{}); ok {
			tls["alpn"] = alpn
		} else {
			outbound["tls"] = map[string]interface{}{"enabled": true, "alpn": alpn}
		}
	}
	if cc := strings.TrimSpace(q.Get("congestion_control")); cc != "" {
		outbound["congestion_control"] = cc
	}
	if mode := strings.TrimSpace(q.Get("udp_relay_mode")); mode != "" {
		outbound["udp_relay_mode"] = mode
	}
	if asString(outbound["server"]) == "" || asInt(outbound["server_port"]) <= 0 || asString(outbound["uuid"]) == "" || asString(outbound["password"]) == "" {
		return nil, errors.New("invalid tuic")
	}
	return outbound, nil
}

func buildClashRootTemplate(upstreamRaw []byte, clashCfg store.ClashConfig) map[string]interface{} {
	if strings.TrimSpace(clashCfg.TemplateMode) == store.ClashTemplateModeCustom && strings.TrimSpace(clashCfg.Template) != "" {
		if m := parseYAMLMap([]byte(clashCfg.Template)); m != nil {
			return m
		}
	}
	if strings.TrimSpace(clashCfg.CustomConfig) != "" {
		if m := parseYAMLMap([]byte(clashCfg.CustomConfig)); m != nil {
			return m
		}
	}
	if m := parseYAMLMap(upstreamRaw); m != nil {
		if _, ok := m["proxies"]; ok {
			return m
		}
	}
	return defaultClashRootTemplate()
}

func defaultClashRootTemplate() map[string]interface{} {
	return map[string]interface{}{
		"mixed-port": 7890,
		"allow-lan":  false,
		"mode":       "rule",
		"log-level":  "info",
		"ipv6":       false,
		"dns": map[string]interface{}{
			"enable":             true,
			"enhanced-mode":      "fake-ip",
			"default-nameserver": []interface{}{"223.5.5.5", "1.1.1.1"},
			"nameserver":         []interface{}{"https://dns.alidns.com/dns-query", "https://1.1.1.1/dns-query"},
		},
	}
}

func parseYAMLMap(raw []byte) map[string]interface{} {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil
	}
	if m == nil {
		return nil
	}
	return m
}

func injectProxyNamesIntoGroups(root map[string]interface{}, proxyNames []string) bool {
	groupsRaw, ok := root["proxy-groups"]
	if !ok {
		return false
	}
	groups, ok := groupsRaw.([]interface{})
	if !ok || len(groups) == 0 {
		return false
	}
	hasAny := false
	for _, item := range groups {
		group, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		now := make([]string, 0)
		if current, ok := group["proxies"].([]interface{}); ok {
			for _, entry := range current {
				name := asString(entry)
				if name != "" {
					now = append(now, name)
				}
			}
		}
		next := dedupeStrings(append(now, proxyNames...))
		if len(next) > 0 {
			hasAny = true
			arr := make([]interface{}, 0, len(next))
			for _, name := range next {
				arr = append(arr, name)
			}
			group["proxies"] = arr
		}
	}
	return hasAny
}

func defaultClashProxyGroups(proxyNames []string) []interface{} {
	names := dedupeStrings(proxyNames)
	proxyValues := make([]interface{}, 0, len(names)+1)
	proxyValues = append(proxyValues, "DIRECT")
	for _, name := range names {
		proxyValues = append(proxyValues, name)
	}
	return []interface{}{
		map[string]interface{}{
			"name":    "PROXY",
			"type":    "select",
			"proxies": proxyValues,
		},
	}
}

func ensureClashRules(root map[string]interface{}, additionalRules []string) {
	rules := make([]interface{}, 0)
	if existing, ok := root["rules"].([]interface{}); ok {
		rules = append(rules, existing...)
	}
	for _, item := range additionalRules {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		rules = append(rules, trimmed)
	}
	if len(rules) == 0 {
		rules = append(rules, "MATCH,PROXY")
	}
	root["rules"] = dedupeRuleInterfaces(rules)
}

func dedupeRuleInterfaces(rules []interface{}) []interface{} {
	seen := make(map[string]struct{}, len(rules))
	result := make([]interface{}, 0, len(rules))
	for _, item := range rules {
		rule := strings.TrimSpace(asString(item))
		if rule == "" {
			continue
		}
		key := strings.ToLower(rule)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, rule)
	}
	return result
}

func uriToClashProxy(line string) (map[string]interface{}, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil, errors.New("empty node")
	}
	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasPrefix(lower, "vmess://"):
		return vmessURIToClashProxy(trimmed)
	case strings.HasPrefix(lower, "vless://"):
		return vlessURIToClashProxy(trimmed)
	case strings.HasPrefix(lower, "trojan://"):
		return trojanURIToClashProxy(trimmed)
	case strings.HasPrefix(lower, "ss://"):
		return ssURIToClashProxy(trimmed)
	case strings.HasPrefix(lower, "ssr://"):
		converted, err := ssrURIToSSURI(trimmed)
		if err != nil {
			return nil, err
		}
		return ssURIToClashProxy(converted)
	case strings.HasPrefix(lower, "socks5://") || strings.HasPrefix(lower, "socks://"):
		return socks5URIToClashProxy(trimmed)
	case strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://"):
		return httpURIToClashProxy(trimmed)
	case strings.HasPrefix(lower, "wireguard://") || strings.HasPrefix(lower, "wg://"):
		return wireguardURIToClashProxy(trimmed)
	case strings.HasPrefix(lower, "hysteria://") || strings.HasPrefix(lower, "hy://"):
		return hysteriaURIToClashProxy(trimmed)
	case strings.HasPrefix(lower, "hysteria2://") || strings.HasPrefix(lower, "hy2://"):
		return hysteria2URIToClashProxy(trimmed)
	case strings.HasPrefix(lower, "tuic://"):
		return tuicURIToClashProxy(trimmed)
	default:
		return nil, errors.New("unsupported clash protocol")
	}
}

func vmessURIToClashProxy(line string) (map[string]interface{}, error) {
	core, _ := splitCoreAndFragment(line)
	payload := strings.TrimPrefix(core, "vmess://")
	decoded, err := decodeBase64Loose(payload)
	if err != nil {
		return nil, err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		return nil, err
	}
	name := asString(cfg["ps"])
	if name == "" {
		name = "vmess"
	}
	proxy := map[string]interface{}{
		"name":   name,
		"type":   "vmess",
		"server": fallbackString(asString(cfg["add"]), asString(cfg["host"])),
		"port":   parsePort(asString(cfg["port"])),
		"uuid":   asString(cfg["id"]),
		"cipher": fallbackString(asString(cfg["scy"]), "auto"),
		"alterId": func() int {
			v, _ := strconv.Atoi(fallbackString(asString(cfg["aid"]), "0"))
			return v
		}(),
		"network": fallbackString(asString(cfg["net"]), "tcp"),
		"udp":     true,
	}
	if tls := strings.ToLower(asString(cfg["tls"])); tls == "tls" || tls == "true" {
		proxy["tls"] = true
	}
	if sni := asString(cfg["sni"]); sni != "" {
		proxy["servername"] = sni
	} else if host := asString(cfg["host"]); host != "" {
		proxy["servername"] = host
	}
	if path := asString(cfg["path"]); path != "" {
		if strings.EqualFold(asString(cfg["net"]), "ws") {
			wsOpts := map[string]interface{}{"path": path}
			if host := asString(cfg["host"]); host != "" {
				wsOpts["headers"] = map[string]interface{}{"Host": host}
			}
			proxy["ws-opts"] = wsOpts
		}
	}
	if strings.EqualFold(asString(cfg["net"]), "grpc") {
		serviceName := firstNonEmpty(asString(cfg["serviceName"]), asString(cfg["path"]))
		if serviceName != "" {
			proxy["grpc-opts"] = map[string]interface{}{"grpc-service-name": serviceName}
		}
	}
	if fp := asString(cfg["fp"]); fp != "" {
		proxy["client-fingerprint"] = fp
	}
	if asString(proxy["server"]) == "" || asInt(proxy["port"]) <= 0 || asString(proxy["uuid"]) == "" {
		return nil, errors.New("invalid vmess")
	}
	return proxy, nil
}

func vlessURIToClashProxy(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "vless"
	}
	proxy := map[string]interface{}{
		"name":       name,
		"type":       "vless",
		"server":     u.Hostname(),
		"port":       parsePort(u.Port()),
		"uuid":       strings.TrimSpace(u.User.Username()),
		"network":    fallbackString(q.Get("type"), "tcp"),
		"tls":        strings.EqualFold(q.Get("security"), "tls") || strings.EqualFold(q.Get("security"), "reality"),
		"servername": q.Get("sni"),
		"udp":        true,
	}
	if flow := strings.TrimSpace(q.Get("flow")); flow != "" {
		proxy["flow"] = flow
	}
	if fp := strings.TrimSpace(q.Get("fp")); fp != "" {
		proxy["client-fingerprint"] = fp
	}
	if parseBoolString(q.Get("allowInsecure")) {
		proxy["skip-cert-verify"] = true
	}
	if strings.EqualFold(q.Get("security"), "reality") {
		reality := map[string]interface{}{}
		if pbk := strings.TrimSpace(q.Get("pbk")); pbk != "" {
			reality["public-key"] = pbk
		}
		if sid := strings.TrimSpace(q.Get("sid")); sid != "" {
			reality["short-id"] = sid
		}
		if len(reality) > 0 {
			proxy["reality-opts"] = reality
		}
	}
	network := strings.ToLower(strings.TrimSpace(q.Get("type")))
	if network == "ws" {
		wsOpts := map[string]interface{}{}
		if path := strings.TrimSpace(q.Get("path")); path != "" {
			wsOpts["path"] = path
		}
		if host := strings.TrimSpace(q.Get("host")); host != "" {
			wsOpts["headers"] = map[string]interface{}{"Host": host}
		}
		if len(wsOpts) > 0 {
			proxy["ws-opts"] = wsOpts
		}
	} else if network == "grpc" {
		if serviceName := firstNonEmpty(strings.TrimSpace(q.Get("serviceName")), strings.TrimSpace(q.Get("service_name"))); serviceName != "" {
			proxy["grpc-opts"] = map[string]interface{}{"grpc-service-name": serviceName}
		}
	}
	if asString(proxy["server"]) == "" || asInt(proxy["port"]) <= 0 || asString(proxy["uuid"]) == "" {
		return nil, errors.New("invalid vless")
	}
	return proxy, nil
}

func trojanURIToClashProxy(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "trojan"
	}
	password, _ := u.User.Password()
	if password == "" {
		password = u.User.Username()
	}
	proxy := map[string]interface{}{
		"name":       name,
		"type":       "trojan",
		"server":     u.Hostname(),
		"port":       parsePort(u.Port()),
		"password":   password,
		"sni":        q.Get("sni"),
		"servername": q.Get("sni"),
		"udp":        true,
	}
	if fp := strings.TrimSpace(q.Get("fp")); fp != "" {
		proxy["client-fingerprint"] = fp
	}
	if parseBoolString(q.Get("allowInsecure")) {
		proxy["skip-cert-verify"] = true
	}
	network := strings.ToLower(strings.TrimSpace(q.Get("type")))
	if network != "" {
		proxy["network"] = network
	}
	if network == "ws" {
		wsOpts := map[string]interface{}{}
		if path := strings.TrimSpace(q.Get("path")); path != "" {
			wsOpts["path"] = path
		}
		if host := strings.TrimSpace(q.Get("host")); host != "" {
			wsOpts["headers"] = map[string]interface{}{"Host": host}
		}
		if len(wsOpts) > 0 {
			proxy["ws-opts"] = wsOpts
		}
	} else if network == "grpc" {
		if serviceName := firstNonEmpty(strings.TrimSpace(q.Get("serviceName")), strings.TrimSpace(q.Get("service_name"))); serviceName != "" {
			proxy["grpc-opts"] = map[string]interface{}{"grpc-service-name": serviceName}
		}
	}
	if asString(proxy["server"]) == "" || asInt(proxy["port"]) <= 0 || asString(proxy["password"]) == "" {
		return nil, errors.New("invalid trojan")
	}
	return proxy, nil
}

func ssURIToClashProxy(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "ss"
	}
	method := ""
	password := ""
	if u.User != nil {
		method = u.User.Username()
		password, _ = u.User.Password()
	}
	if password == "" || strings.Contains(method, "=") {
		payload := strings.TrimPrefix(core, "ss://")
		if idx := strings.Index(payload, "@"); idx >= 0 {
			userinfo := payload[:idx]
			if decoded, err := decodeBase64Loose(userinfo); err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					method = strings.TrimSpace(parts[0])
					password = strings.TrimSpace(parts[1])
				}
			}
		}
	}
	proxy := map[string]interface{}{
		"name":     name,
		"type":     "ss",
		"server":   u.Hostname(),
		"port":     parsePort(u.Port()),
		"cipher":   method,
		"password": password,
		"udp":      true,
	}
	if asString(proxy["server"]) == "" || asInt(proxy["port"]) <= 0 || asString(proxy["password"]) == "" || asString(proxy["cipher"]) == "" {
		return nil, errors.New("invalid ss")
	}
	return proxy, nil
}

func socks5URIToClashProxy(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "socks5"
	}
	proxy := map[string]interface{}{
		"name":   name,
		"type":   "socks5",
		"server": u.Hostname(),
		"port":   parsePort(u.Port()),
		"udp":    true,
	}
	if u.User != nil {
		if username := strings.TrimSpace(u.User.Username()); username != "" {
			proxy["username"] = username
		}
		if password, _ := u.User.Password(); strings.TrimSpace(password) != "" {
			proxy["password"] = password
		}
	}
	if asString(proxy["server"]) == "" || asInt(proxy["port"]) <= 0 {
		return nil, errors.New("invalid socks5")
	}
	return proxy, nil
}

func httpURIToClashProxy(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "http"
	}
	proxy := map[string]interface{}{
		"name":   name,
		"type":   "http",
		"server": u.Hostname(),
		"port":   parsePort(u.Port()),
	}
	if u.User != nil {
		if username := strings.TrimSpace(u.User.Username()); username != "" {
			proxy["username"] = username
		}
		if password, _ := u.User.Password(); strings.TrimSpace(password) != "" {
			proxy["password"] = password
		}
	}
	if strings.EqualFold(u.Scheme, "https") {
		proxy["tls"] = true
	}
	if asString(proxy["server"]) == "" || asInt(proxy["port"]) <= 0 {
		return nil, errors.New("invalid http")
	}
	return proxy, nil
}

func wireguardURIToClashProxy(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "wireguard"
	}
	privateKey := strings.TrimSpace(q.Get("privatekey"))
	if privateKey == "" {
		privateKey = strings.TrimSpace(q.Get("private_key"))
	}
	publicKey := strings.TrimSpace(q.Get("publickey"))
	if publicKey == "" {
		publicKey = strings.TrimSpace(q.Get("peer_public_key"))
	}
	proxy := map[string]interface{}{
		"name":        name,
		"type":        "wireguard",
		"server":      u.Hostname(),
		"port":        parsePort(u.Port()),
		"private-key": privateKey,
		"public-key":  publicKey,
	}
	if ip := strings.TrimSpace(q.Get("address")); ip != "" {
		proxy["ip"] = ip
	}
	if reserved := strings.TrimSpace(q.Get("reserved")); reserved != "" {
		proxy["reserved"] = reserved
	}
	if mtu := parsePort(q.Get("mtu")); mtu > 0 {
		proxy["mtu"] = mtu
	}
	if asString(proxy["server"]) == "" || asInt(proxy["port"]) <= 0 || asString(proxy["private-key"]) == "" || asString(proxy["public-key"]) == "" {
		return nil, errors.New("invalid wireguard")
	}
	return proxy, nil
}

func hysteriaURIToClashProxy(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "hysteria"
	}
	auth := strings.TrimSpace(q.Get("auth"))
	if auth == "" {
		auth = strings.TrimSpace(q.Get("auth_str"))
	}
	proxy := map[string]interface{}{
		"name":   name,
		"type":   "hysteria",
		"server": u.Hostname(),
		"port":   parsePort(u.Port()),
	}
	if auth != "" {
		proxy["auth-str"] = auth
	}
	if upMbps := parsePort(q.Get("upmbps")); upMbps > 0 {
		proxy["up"] = strconv.Itoa(upMbps)
	}
	if downMbps := parsePort(q.Get("downmbps")); downMbps > 0 {
		proxy["down"] = strconv.Itoa(downMbps)
	}
	if obfs := strings.TrimSpace(q.Get("obfs")); obfs != "" {
		proxy["obfs"] = obfs
	}
	if sni := strings.TrimSpace(q.Get("sni")); sni != "" {
		proxy["sni"] = sni
	}
	if asString(proxy["server"]) == "" || asInt(proxy["port"]) <= 0 {
		return nil, errors.New("invalid hysteria")
	}
	return proxy, nil
}

func hysteria2URIToClashProxy(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "hysteria2"
	}
	password, _ := u.User.Password()
	if password == "" {
		password = u.User.Username()
	}
	proxy := map[string]interface{}{
		"name":     name,
		"type":     "hysteria2",
		"server":   u.Hostname(),
		"port":     parsePort(u.Port()),
		"password": password,
		"sni":      q.Get("sni"),
	}
	if obfs := strings.TrimSpace(q.Get("obfs")); obfs != "" {
		proxy["obfs"] = obfs
	}
	if pwd := firstNonEmpty(strings.TrimSpace(q.Get("obfs-password")), strings.TrimSpace(q.Get("obfs_password"))); pwd != "" {
		proxy["obfs-password"] = pwd
	}
	if alpn := splitCSV(q.Get("alpn")); len(alpn) > 0 {
		proxy["alpn"] = alpn
	}
	if parseBoolString(q.Get("insecure")) || parseBoolString(q.Get("allowInsecure")) {
		proxy["skip-cert-verify"] = true
	}
	if asString(proxy["server"]) == "" || asInt(proxy["port"]) <= 0 || asString(proxy["password"]) == "" {
		return nil, errors.New("invalid hysteria2")
	}
	return proxy, nil
}

func tuicURIToClashProxy(line string) (map[string]interface{}, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return nil, err
	}
	name, _ := url.QueryUnescape(fragment)
	if name == "" {
		name = "tuic"
	}
	password, _ := u.User.Password()
	proxy := map[string]interface{}{
		"name":     name,
		"type":     "tuic",
		"server":   u.Hostname(),
		"port":     parsePort(u.Port()),
		"uuid":     u.User.Username(),
		"password": password,
	}
	q := u.Query()
	if sni := strings.TrimSpace(q.Get("sni")); sni != "" {
		proxy["sni"] = sni
	}
	if alpn := splitCSV(q.Get("alpn")); len(alpn) > 0 {
		proxy["alpn"] = alpn
	}
	if cc := strings.TrimSpace(q.Get("congestion_control")); cc != "" {
		proxy["congestion-controller"] = cc
	}
	if mode := strings.TrimSpace(q.Get("udp_relay_mode")); mode != "" {
		proxy["udp-relay-mode"] = mode
	}
	if asString(proxy["server"]) == "" || asInt(proxy["port"]) <= 0 || asString(proxy["uuid"]) == "" || asString(proxy["password"]) == "" {
		return nil, errors.New("invalid tuic")
	}
	return proxy, nil
}

func dedupeStrings(list []string) []string {
	seen := make(map[string]struct{}, len(list))
	result := make([]string, 0, len(list))
	for _, item := range list {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func extractSubscriptionLines(body []byte) ([]string, error) {
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return nil, errors.New("空订阅")
	}

	if lines := parseLinesFromSingBoxJSON(raw); len(lines) > 0 {
		return lines, nil
	}
	if lines := parseLinesFromClashYAML(raw); len(lines) > 0 {
		return lines, nil
	}
	if containsURILines(raw) {
		return splitLines(raw), nil
	}
	decoded, err := decodeBase64Loose(raw)
	if err == nil {
		decodedText := strings.TrimSpace(string(decoded))
		if containsURILines(decodedText) {
			return splitLines(decodedText), nil
		}
	}
	return nil, errors.New("不支持的订阅格式")
}

func parseNodeLine(line string) (MergedNode, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return MergedNode{}, errors.New("empty")
	}
	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasPrefix(lower, "vmess://"):
		return parseVMessNode(trimmed)
	case strings.HasPrefix(lower, "ssr://"):
		return parseSSRNode(trimmed)
	default:
		return parseURLNode(trimmed)
	}
}

func parseVMessNode(line string) (MergedNode, error) {
	core, _ := splitCoreAndFragment(line)
	payload := strings.TrimPrefix(core, "vmess://")
	decoded, err := decodeBase64Loose(payload)
	if err != nil {
		return MergedNode{}, err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		return MergedNode{}, err
	}
	name := asString(cfg["ps"])
	host := asString(cfg["add"])
	if host == "" {
		host = asString(cfg["host"])
	}
	port, _ := strconv.Atoi(asString(cfg["port"]))
	return MergedNode{
		Protocol: "vmess",
		Name:     name,
		Host:     host,
		Port:     port,
		render: func(name string) (string, error) {
			copied := make(map[string]interface{}, len(cfg))
			for k, v := range cfg {
				copied[k] = v
			}
			copied["ps"] = name
			buf, err := json.Marshal(copied)
			if err != nil {
				return "", err
			}
			return "vmess://" + base64.StdEncoding.EncodeToString(buf), nil
		},
	}, nil
}

func parseSSRNode(line string) (MergedNode, error) {
	payload := strings.TrimPrefix(line, "ssr://")
	decoded, err := decodeBase64Loose(payload)
	if err != nil {
		return MergedNode{}, err
	}
	mainPart := string(decoded)
	queryPart := ""
	if idx := strings.Index(mainPart, "/?"); idx >= 0 {
		queryPart = mainPart[idx+2:]
		mainPart = mainPart[:idx]
	}
	parts := strings.Split(mainPart, ":")
	if len(parts) < 6 {
		return MergedNode{}, errors.New("invalid ssr")
	}
	host := strings.TrimSpace(parts[0])
	port, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
	params, _ := url.ParseQuery(queryPart)
	name := ""
	if raw := strings.TrimSpace(params.Get("remarks")); raw != "" {
		if nameBytes, err := decodeBase64Loose(raw); err == nil {
			name = strings.TrimSpace(string(nameBytes))
		}
	}
	return MergedNode{
		Protocol: "ssr",
		Name:     name,
		Host:     host,
		Port:     port,
		render: func(name string) (string, error) {
			next := url.Values{}
			for key, values := range params {
				next[key] = append([]string(nil), values...)
			}
			next.Set("remarks", base64.RawURLEncoding.EncodeToString([]byte(name)))
			rebuilt := mainPart
			encodedQuery := next.Encode()
			if encodedQuery != "" {
				rebuilt += "/?" + encodedQuery
			}
			return "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(rebuilt)), nil
		},
	}, nil
}

func ssrURIToSSURI(line string) (string, error) {
	payload := strings.TrimPrefix(strings.TrimSpace(line), "ssr://")
	decoded, err := decodeBase64Loose(payload)
	if err != nil {
		return "", err
	}
	raw := string(decoded)
	mainPart := raw
	queryPart := ""
	if idx := strings.Index(raw, "/?"); idx >= 0 {
		mainPart = raw[:idx]
		queryPart = raw[idx+2:]
	}
	parts := strings.Split(mainPart, ":")
	if len(parts) < 6 {
		return "", errors.New("invalid ssr")
	}
	host := strings.TrimSpace(parts[0])
	port := strings.TrimSpace(parts[1])
	method := strings.TrimSpace(parts[3])
	passwordEncoded := strings.TrimSpace(parts[5])
	passwordDecoded, err := decodeBase64Loose(passwordEncoded)
	if err != nil {
		return "", err
	}
	password := strings.TrimSpace(string(passwordDecoded))
	if host == "" || port == "" || method == "" || password == "" {
		return "", errors.New("invalid ssr")
	}
	name := ""
	if queryPart != "" {
		params, _ := url.ParseQuery(queryPart)
		if remarks := strings.TrimSpace(params.Get("remarks")); remarks != "" {
			if text, decErr := decodeBase64Loose(remarks); decErr == nil {
				name = strings.TrimSpace(string(text))
			}
		}
	}
	userinfo := base64.StdEncoding.EncodeToString([]byte(method + ":" + password))
	ss := "ss://" + strings.TrimRight(userinfo, "=") + "@" + host + ":" + port
	if name != "" {
		ss += "#" + url.QueryEscape(name)
	}
	return ss, nil
}

func parseURLNode(line string) (MergedNode, error) {
	core, fragment := splitCoreAndFragment(line)
	u, err := url.Parse(core)
	if err != nil {
		return MergedNode{}, err
	}
	scheme := normalizeProtocol(u.Scheme)
	host := strings.TrimSpace(u.Hostname())
	port := parsePort(u.Port())
	if scheme == "ss" {
		if ssHost, ssPort := parseSSHostPort(core); ssHost != "" {
			host = ssHost
			port = ssPort
		}
	}
	name, _ := url.QueryUnescape(fragment)
	return MergedNode{
		Protocol: scheme,
		Name:     name,
		Host:     host,
		Port:     port,
		render: func(name string) (string, error) {
			if strings.TrimSpace(name) == "" {
				return core, nil
			}
			return core + "#" + url.QueryEscape(name), nil
		},
	}, nil
}

func parseSSHostPort(raw string) (string, int) {
	core, _ := splitCoreAndFragment(raw)
	u, err := url.Parse(core)
	if err == nil && u.Hostname() != "" {
		return u.Hostname(), parsePort(u.Port())
	}
	payload := strings.TrimPrefix(core, "ss://")
	if idx := strings.Index(payload, "?"); idx >= 0 {
		payload = payload[:idx]
	}
	if decoded, err := decodeBase64Loose(payload); err == nil {
		segment := string(decoded)
		if at := strings.LastIndex(segment, "@"); at >= 0 {
			hostPort := segment[at+1:]
			if h, p, err := net.SplitHostPort(hostPort); err == nil {
				port, _ := strconv.Atoi(strings.TrimSpace(p))
				return h, port
			}
			if idx := strings.LastIndex(hostPort, ":"); idx > 0 {
				port, _ := strconv.Atoi(hostPort[idx+1:])
				return hostPort[:idx], port
			}
		}
	}
	return "", 0
}

func parseLinesFromClashYAML(raw string) []string {
	var root map[string]interface{}
	if err := yaml.Unmarshal([]byte(raw), &root); err != nil {
		return nil
	}
	proxies, ok := root["proxies"].([]interface{})
	if !ok {
		if fallback, ok2 := root["Proxy"].([]interface{}); ok2 {
			proxies = fallback
		} else {
			return nil
		}
	}
	lines := make([]string, 0, len(proxies))
	for _, item := range proxies {
		proxyMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if line := clashProxyToURI(proxyMap); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func clashProxyToURI(proxy map[string]interface{}) string {
	typeName := strings.ToLower(strings.TrimSpace(asString(proxy["type"])))
	name := asString(proxy["name"])
	server := asString(proxy["server"])
	port := asInt(proxy["port"])
	if server == "" || port <= 0 {
		return ""
	}
	switch typeName {
	case "vmess":
		cfg := map[string]interface{}{
			"v":    "2",
			"ps":   name,
			"add":  server,
			"port": strconv.Itoa(port),
			"id":   asString(proxy["uuid"]),
			"aid":  strconv.Itoa(asInt(proxy["alterId"])),
			"scy":  fallbackString(asString(proxy["cipher"]), "auto"),
			"net":  fallbackString(asString(proxy["network"]), "tcp"),
		}
		if tls, ok := proxy["tls"].(bool); ok && tls {
			cfg["tls"] = "tls"
		}
		if sni := asString(proxy["servername"]); sni != "" {
			cfg["sni"] = sni
		}
		if fp := asString(proxy["client-fingerprint"]); fp != "" {
			cfg["fp"] = fp
		}
		if ws, ok := proxy["ws-opts"].(map[string]interface{}); ok {
			cfg["net"] = "ws"
			cfg["path"] = asString(ws["path"])
			if headers, ok := ws["headers"].(map[string]interface{}); ok {
				cfg["host"] = asString(headers["Host"])
			}
		}
		if grpc, ok := proxy["grpc-opts"].(map[string]interface{}); ok {
			cfg["net"] = "grpc"
			if serviceName := asString(grpc["grpc-service-name"]); serviceName != "" {
				cfg["serviceName"] = serviceName
			}
		}
		buf, err := json.Marshal(cfg)
		if err != nil {
			return ""
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(buf)
	case "vless":
		q := url.Values{}
		q.Set("encryption", "none")
		if network := asString(proxy["network"]); network != "" {
			q.Set("type", network)
		}
		if ws, ok := proxy["ws-opts"].(map[string]interface{}); ok {
			q.Set("type", "ws")
			if path := asString(ws["path"]); path != "" {
				q.Set("path", path)
			}
			if headers, ok := ws["headers"].(map[string]interface{}); ok {
				if host := asString(headers["Host"]); host != "" {
					q.Set("host", host)
				}
			}
		}
		if grpc, ok := proxy["grpc-opts"].(map[string]interface{}); ok {
			q.Set("type", "grpc")
			if serviceName := asString(grpc["grpc-service-name"]); serviceName != "" {
				q.Set("serviceName", serviceName)
			}
		}
		if flow := asString(proxy["flow"]); flow != "" {
			q.Set("flow", flow)
		}
		if fp := asString(proxy["client-fingerprint"]); fp != "" {
			q.Set("fp", fp)
		}
		if parseBoolString(asString(proxy["skip-cert-verify"])) {
			q.Set("allowInsecure", "1")
		}
		if reality, ok := proxy["reality-opts"].(map[string]interface{}); ok {
			q.Set("security", "reality")
			if pbk := asString(reality["public-key"]); pbk != "" {
				q.Set("pbk", pbk)
			}
			if sid := asString(reality["short-id"]); sid != "" {
				q.Set("sid", sid)
			}
		} else if tls, ok := proxy["tls"].(bool); ok && tls {
			q.Set("security", "tls")
		}
		if sni := asString(proxy["servername"]); sni != "" {
			q.Set("sni", sni)
		}
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s", url.QueryEscape(asString(proxy["uuid"])), server, port, q.Encode(), url.QueryEscape(name))
	case "trojan":
		q := url.Values{}
		if sni := asString(proxy["sni"]); sni != "" {
			q.Set("sni", sni)
		}
		if network := asString(proxy["network"]); network != "" {
			q.Set("type", network)
		}
		if ws, ok := proxy["ws-opts"].(map[string]interface{}); ok {
			q.Set("type", "ws")
			if path := asString(ws["path"]); path != "" {
				q.Set("path", path)
			}
			if headers, ok := ws["headers"].(map[string]interface{}); ok {
				if host := asString(headers["Host"]); host != "" {
					q.Set("host", host)
				}
			}
		}
		if grpc, ok := proxy["grpc-opts"].(map[string]interface{}); ok {
			q.Set("type", "grpc")
			if serviceName := asString(grpc["grpc-service-name"]); serviceName != "" {
				q.Set("serviceName", serviceName)
			}
		}
		if fp := asString(proxy["client-fingerprint"]); fp != "" {
			q.Set("fp", fp)
		}
		if parseBoolString(asString(proxy["skip-cert-verify"])) {
			q.Set("allowInsecure", "1")
		}
		return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", url.QueryEscape(asString(proxy["password"])), server, port, q.Encode(), url.QueryEscape(name))
	case "ss":
		method := asString(proxy["cipher"])
		password := asString(proxy["password"])
		userinfo := base64.StdEncoding.EncodeToString([]byte(method + ":" + password))
		return fmt.Sprintf("ss://%s@%s:%d#%s", strings.TrimRight(userinfo, "="), server, port, url.QueryEscape(name))
	case "ssr":
		method := asString(proxy["cipher"])
		password := asString(proxy["password"])
		userinfo := base64.StdEncoding.EncodeToString([]byte(method + ":" + password))
		return fmt.Sprintf("ss://%s@%s:%d#%s", strings.TrimRight(userinfo, "="), server, port, url.QueryEscape(name))
	case "socks5", "socks":
		auth := ""
		if username := asString(proxy["username"]); username != "" {
			auth = username
			if password := asString(proxy["password"]); password != "" {
				auth += ":" + password
			}
			auth += "@"
		}
		return fmt.Sprintf("socks5://%s%s:%d#%s", auth, server, port, url.QueryEscape(name))
	case "http":
		scheme := "http"
		if tls, ok := proxy["tls"].(bool); ok && tls {
			scheme = "https"
		}
		auth := ""
		if username := asString(proxy["username"]); username != "" {
			auth = username
			if password := asString(proxy["password"]); password != "" {
				auth += ":" + password
			}
			auth += "@"
		}
		return fmt.Sprintf("%s://%s%s:%d#%s", scheme, auth, server, port, url.QueryEscape(name))
	case "wireguard":
		q := url.Values{}
		if privateKey := asString(proxy["private-key"]); privateKey != "" {
			q.Set("privatekey", privateKey)
		}
		if publicKey := asString(proxy["public-key"]); publicKey != "" {
			q.Set("publickey", publicKey)
		}
		if ip := asString(proxy["ip"]); ip != "" {
			q.Set("address", ip)
		}
		if reserved := asString(proxy["reserved"]); reserved != "" {
			q.Set("reserved", reserved)
		}
		if mtu := asInt(proxy["mtu"]); mtu > 0 {
			q.Set("mtu", strconv.Itoa(mtu))
		}
		return fmt.Sprintf("wireguard://%s:%d?%s#%s", server, port, q.Encode(), url.QueryEscape(name))
	case "hysteria":
		q := url.Values{}
		if auth := asString(proxy["auth-str"]); auth != "" {
			q.Set("auth", auth)
		}
		if up := asString(proxy["up"]); up != "" {
			q.Set("upmbps", up)
		}
		if down := asString(proxy["down"]); down != "" {
			q.Set("downmbps", down)
		}
		if obfs := asString(proxy["obfs"]); obfs != "" {
			q.Set("obfs", obfs)
		}
		if sni := asString(proxy["sni"]); sni != "" {
			q.Set("sni", sni)
		}
		return fmt.Sprintf("hysteria://%s:%d?%s#%s", server, port, q.Encode(), url.QueryEscape(name))
	case "hysteria2", "hy2":
		password := asString(proxy["password"])
		q := url.Values{}
		if sni := asString(proxy["sni"]); sni != "" {
			q.Set("sni", sni)
		}
		if obfs := asString(proxy["obfs"]); obfs != "" {
			q.Set("obfs", obfs)
		}
		if obfsPassword := asString(proxy["obfs-password"]); obfsPassword != "" {
			q.Set("obfs-password", obfsPassword)
		}
		if alpn := anySliceToCSV(proxy["alpn"]); alpn != "" {
			q.Set("alpn", alpn)
		}
		if parseBoolString(asString(proxy["skip-cert-verify"])) {
			q.Set("insecure", "1")
		}
		return fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s", url.QueryEscape(password), server, port, q.Encode(), url.QueryEscape(name))
	case "tuic":
		uuid := asString(proxy["uuid"])
		password := asString(proxy["password"])
		q := url.Values{}
		if sni := asString(proxy["sni"]); sni != "" {
			q.Set("sni", sni)
		}
		if alpn := anySliceToCSV(proxy["alpn"]); alpn != "" {
			q.Set("alpn", alpn)
		}
		if cc := asString(proxy["congestion-controller"]); cc != "" {
			q.Set("congestion_control", cc)
		}
		if mode := asString(proxy["udp-relay-mode"]); mode != "" {
			q.Set("udp_relay_mode", mode)
		}
		return fmt.Sprintf("tuic://%s:%s@%s:%d?%s#%s", url.QueryEscape(uuid), url.QueryEscape(password), server, port, q.Encode(), url.QueryEscape(name))
	default:
		return ""
	}
}

func parseLinesFromSingBoxJSON(raw string) []string {
	var root map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return nil
	}
	outbounds, ok := root["outbounds"].([]interface{})
	if !ok {
		return nil
	}
	lines := make([]string, 0, len(outbounds))
	for _, item := range outbounds {
		outbound, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typeName := strings.ToLower(strings.TrimSpace(asString(outbound["type"])))
		name := fallbackString(asString(outbound["tag"]), asString(outbound["name"]))
		server := asString(outbound["server"])
		port := asInt(outbound["server_port"])
		if server == "" || port <= 0 {
			continue
		}
		switch typeName {
		case "vmess":
			cfg := map[string]interface{}{"v": "2", "ps": name, "add": server, "port": strconv.Itoa(port), "id": asString(outbound["uuid"]), "aid": "0", "net": fallbackString(asString(outbound["network"]), "tcp")}
			cfg["scy"] = fallbackString(asString(outbound["security"]), "auto")
			if tls, ok := outbound["tls"].(map[string]interface{}); ok {
				if enabled, ok := tls["enabled"].(bool); ok && enabled {
					cfg["tls"] = "tls"
				}
				if sni := asString(tls["server_name"]); sni != "" {
					cfg["sni"] = sni
				}
			}
			if transport, ok := outbound["transport"].(map[string]interface{}); ok {
				if transportType := asString(transport["type"]); transportType != "" {
					cfg["net"] = transportType
				}
				if path := asString(transport["path"]); path != "" {
					cfg["path"] = path
				}
				if headers, ok := transport["headers"].(map[string]interface{}); ok {
					if host := asString(headers["Host"]); host != "" {
						cfg["host"] = host
					}
				}
				if serviceName := asString(transport["service_name"]); serviceName != "" {
					cfg["serviceName"] = serviceName
				}
			}
			buf, err := json.Marshal(cfg)
			if err != nil {
				continue
			}
			lines = append(lines, "vmess://"+base64.StdEncoding.EncodeToString(buf))
		case "vless":
			q := url.Values{}
			q.Set("encryption", "none")
			if network := asString(outbound["network"]); network != "" {
				q.Set("type", network)
			}
			if flow := asString(outbound["flow"]); flow != "" {
				q.Set("flow", flow)
			}
			if tls, ok := outbound["tls"].(map[string]interface{}); ok {
				if enabled, ok := tls["enabled"].(bool); ok && enabled {
					if _, ok := tls["reality"].(map[string]interface{}); ok {
						q.Set("security", "reality")
					} else {
						q.Set("security", "tls")
					}
				}
				if sni := asString(tls["server_name"]); sni != "" {
					q.Set("sni", sni)
				}
				if insecure := parseBoolString(asString(tls["insecure"])); insecure {
					q.Set("allowInsecure", "1")
				}
				if utls, ok := tls["utls"].(map[string]interface{}); ok {
					if fp := asString(utls["fingerprint"]); fp != "" {
						q.Set("fp", fp)
					}
				}
				if reality, ok := tls["reality"].(map[string]interface{}); ok {
					if pbk := asString(reality["public_key"]); pbk != "" {
						q.Set("pbk", pbk)
					}
					if sid := asString(reality["short_id"]); sid != "" {
						q.Set("sid", sid)
					}
					if spider := asString(reality["spider_x"]); spider != "" {
						q.Set("spx", spider)
					}
				}
			}
			if transport, ok := outbound["transport"].(map[string]interface{}); ok {
				if transportType := asString(transport["type"]); transportType != "" {
					q.Set("type", transportType)
				}
				if path := asString(transport["path"]); path != "" {
					q.Set("path", path)
				}
				if headers, ok := transport["headers"].(map[string]interface{}); ok {
					if host := asString(headers["Host"]); host != "" {
						q.Set("host", host)
					}
				}
				if serviceName := asString(transport["service_name"]); serviceName != "" {
					q.Set("serviceName", serviceName)
				}
			}
			lines = append(lines, fmt.Sprintf("vless://%s@%s:%d?%s#%s", url.QueryEscape(asString(outbound["uuid"])), server, port, q.Encode(), url.QueryEscape(name)))
		case "trojan":
			q := url.Values{}
			if tls, ok := outbound["tls"].(map[string]interface{}); ok {
				if sni := asString(tls["server_name"]); sni != "" {
					q.Set("sni", sni)
				}
				if insecure := parseBoolString(asString(tls["insecure"])); insecure {
					q.Set("allowInsecure", "1")
				}
				if utls, ok := tls["utls"].(map[string]interface{}); ok {
					if fp := asString(utls["fingerprint"]); fp != "" {
						q.Set("fp", fp)
					}
				}
			}
			if network := asString(outbound["network"]); network != "" {
				q.Set("type", network)
			}
			if transport, ok := outbound["transport"].(map[string]interface{}); ok {
				if transportType := asString(transport["type"]); transportType != "" {
					q.Set("type", transportType)
				}
				if path := asString(transport["path"]); path != "" {
					q.Set("path", path)
				}
				if headers, ok := transport["headers"].(map[string]interface{}); ok {
					if host := asString(headers["Host"]); host != "" {
						q.Set("host", host)
					}
				}
				if serviceName := asString(transport["service_name"]); serviceName != "" {
					q.Set("serviceName", serviceName)
				}
			}
			if len(q) > 0 {
				lines = append(lines, fmt.Sprintf("trojan://%s@%s:%d?%s#%s", url.QueryEscape(asString(outbound["password"])), server, port, q.Encode(), url.QueryEscape(name)))
			} else {
				lines = append(lines, fmt.Sprintf("trojan://%s@%s:%d#%s", url.QueryEscape(asString(outbound["password"])), server, port, url.QueryEscape(name)))
			}
		case "shadowsocks":
			userinfo := base64.StdEncoding.EncodeToString([]byte(asString(outbound["method"]) + ":" + asString(outbound["password"])))
			lines = append(lines, fmt.Sprintf("ss://%s@%s:%d#%s", strings.TrimRight(userinfo, "="), server, port, url.QueryEscape(name)))
		case "hysteria2":
			q := url.Values{}
			if tls, ok := outbound["tls"].(map[string]interface{}); ok {
				if sni := asString(tls["server_name"]); sni != "" {
					q.Set("sni", sni)
				}
				if insecure := parseBoolString(asString(tls["insecure"])); insecure {
					q.Set("insecure", "1")
				}
				if alpn := anySliceToCSV(tls["alpn"]); alpn != "" {
					q.Set("alpn", alpn)
				}
			}
			if obfs, ok := outbound["obfs"].(map[string]interface{}); ok {
				if obfsType := asString(obfs["type"]); obfsType != "" {
					q.Set("obfs", obfsType)
				}
				if obfsPwd := asString(obfs["password"]); obfsPwd != "" {
					q.Set("obfs-password", obfsPwd)
				}
			}
			lines = append(lines, fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s", url.QueryEscape(asString(outbound["password"])), server, port, q.Encode(), url.QueryEscape(name)))
		case "tuic":
			q := url.Values{}
			if tls, ok := outbound["tls"].(map[string]interface{}); ok {
				if sni := asString(tls["server_name"]); sni != "" {
					q.Set("sni", sni)
				}
				if alpn := anySliceToCSV(tls["alpn"]); alpn != "" {
					q.Set("alpn", alpn)
				}
			}
			if cc := asString(outbound["congestion_control"]); cc != "" {
				q.Set("congestion_control", cc)
			}
			if mode := asString(outbound["udp_relay_mode"]); mode != "" {
				q.Set("udp_relay_mode", mode)
			}
			lines = append(lines, fmt.Sprintf("tuic://%s:%s@%s:%d?%s#%s", url.QueryEscape(asString(outbound["uuid"])), url.QueryEscape(asString(outbound["password"])), server, port, q.Encode(), url.QueryEscape(name)))
		case "shadowsocksr":
			userinfo := base64.StdEncoding.EncodeToString([]byte(asString(outbound["method"]) + ":" + asString(outbound["password"])))
			lines = append(lines, fmt.Sprintf("ss://%s@%s:%d#%s", strings.TrimRight(userinfo, "="), server, port, url.QueryEscape(name)))
		case "socks":
			auth := ""
			if username := asString(outbound["username"]); username != "" {
				auth = username
				if password := asString(outbound["password"]); password != "" {
					auth += ":" + password
				}
				auth += "@"
			}
			lines = append(lines, fmt.Sprintf("socks5://%s%s:%d#%s", auth, server, port, url.QueryEscape(name)))
		case "http":
			scheme := "http"
			if tls, ok := outbound["tls"].(map[string]interface{}); ok {
				if enabled, ok := tls["enabled"].(bool); ok && enabled {
					scheme = "https"
				}
			}
			auth := ""
			if username := asString(outbound["username"]); username != "" {
				auth = username
				if password := asString(outbound["password"]); password != "" {
					auth += ":" + password
				}
				auth += "@"
			}
			lines = append(lines, fmt.Sprintf("%s://%s%s:%d#%s", scheme, auth, server, port, url.QueryEscape(name)))
		case "wireguard":
			q := url.Values{}
			if privateKey := asString(outbound["private_key"]); privateKey != "" {
				q.Set("privatekey", privateKey)
			}
			if peerKey := asString(outbound["peer_public_key"]); peerKey != "" {
				q.Set("publickey", peerKey)
			}
			if addrs, ok := outbound["local_address"].([]interface{}); ok && len(addrs) > 0 {
				parts := make([]string, 0, len(addrs))
				for _, item := range addrs {
					value := asString(item)
					if value != "" {
						parts = append(parts, value)
					}
				}
				if len(parts) > 0 {
					q.Set("address", strings.Join(parts, ","))
				}
			}
			lines = append(lines, fmt.Sprintf("wireguard://%s:%d?%s#%s", server, port, q.Encode(), url.QueryEscape(name)))
		case "hysteria":
			q := url.Values{}
			if auth := asString(outbound["auth_str"]); auth != "" {
				q.Set("auth", auth)
			}
			if up := asInt(outbound["up_mbps"]); up > 0 {
				q.Set("upmbps", strconv.Itoa(up))
			}
			if down := asInt(outbound["down_mbps"]); down > 0 {
				q.Set("downmbps", strconv.Itoa(down))
			}
			lines = append(lines, fmt.Sprintf("hysteria://%s:%d?%s#%s", server, port, q.Encode(), url.QueryEscape(name)))
		}
	}
	return lines
}

func containsURILines(raw string) bool {
	for _, line := range splitLines(raw) {
		if strings.Contains(line, "://") {
			return true
		}
	}
	return false
}

func splitLines(raw string) []string {
	lines := strings.Split(raw, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

func splitCoreAndFragment(raw string) (string, string) {
	idx := strings.LastIndex(raw, "#")
	if idx < 0 {
		return raw, ""
	}
	return raw[:idx], raw[idx+1:]
}

func normalizeProtocol(raw string) string {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	switch trimmed {
	case "hy2", "hysteria2":
		return "hysteria2"
	case "hy", "hysteria":
		return "hysteria"
	case "wg", "wireguard":
		return "wireguard"
	case "socks", "socks5h":
		return "socks5"
	default:
		return trimmed
	}
}

func splitCSV(raw string) []string {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	result := make([]string, 0, len(parts))
	for _, item := range parts {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func parseBoolString(raw string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	switch trimmed {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func anySliceToCSV(value interface{}) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	if list, ok := value.([]string); ok {
		parts := make([]string, 0, len(list))
		for _, item := range list {
			trimmed := strings.TrimSpace(item)
			if trimmed != "" {
				parts = append(parts, trimmed)
			}
		}
		return strings.Join(parts, ",")
	}
	if list, ok := value.([]interface{}); ok {
		parts := make([]string, 0, len(list))
		for _, item := range list {
			trimmed := asString(item)
			if trimmed != "" {
				parts = append(parts, trimmed)
			}
		}
		return strings.Join(parts, ",")
	}
	return ""
}

func parsePort(raw string) int {
	value, _ := strconv.Atoi(strings.TrimSpace(raw))
	return value
}

func decodeBase64Loose(input string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', ' ':
			return -1
		default:
			return r
		}
	}, strings.TrimSpace(input))
	if cleaned == "" {
		return nil, errors.New("empty base64")
	}
	tryDecode := func(enc *base64.Encoding, value string) ([]byte, error) {
		if mod := len(value) % 4; mod != 0 {
			value += strings.Repeat("=", 4-mod)
		}
		return enc.DecodeString(value)
	}
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, enc := range encodings {
		if out, err := tryDecode(enc, cleaned); err == nil {
			return out, nil
		}
	}
	return nil, errors.New("invalid base64")
}

func matchNameIncludes(name string, includes []string) bool {
	if len(includes) == 0 {
		return true
	}
	nameLower := strings.ToLower(name)
	for _, item := range includes {
		if matchesNameToken(nameLower, item) {
			return true
		}
	}
	return false
}

func matchNameExcludes(name string, excludes []string) bool {
	nameLower := strings.ToLower(name)
	for _, item := range excludes {
		if matchesNameToken(nameLower, item) {
			return true
		}
	}
	return false
}

func matchesNameToken(nameLower string, token string) bool {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return false
	}
	if pattern, ok := unwrapRegexPattern(trimmed); ok {
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return false
		}
		return re.MatchString(nameLower)
	}
	return strings.Contains(nameLower, strings.ToLower(trimmed))
}

func unwrapRegexPattern(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "re:") {
		return strings.TrimSpace(trimmed[3:]), true
	}
	if strings.HasPrefix(lower, "regex:") {
		return strings.TrimSpace(trimmed[6:]), true
	}
	if len(trimmed) >= 2 && strings.HasPrefix(trimmed, "/") && strings.HasSuffix(trimmed, "/") {
		return strings.TrimSpace(trimmed[1 : len(trimmed)-1]), true
	}
	if strings.ContainsAny(trimmed, "|()[]{}+*?^$") {
		return trimmed, true
	}
	return "", false
}

func matchRules(node MergedNode, rules []store.MergeRule) bool {
	for _, rule := range rules {
		if !matchRule(node, rule) {
			return false
		}
	}
	return true
}

func matchRule(node MergedNode, rule store.MergeRule) bool {
	field := strings.ToLower(strings.TrimSpace(rule.Field))
	op := strings.ToLower(strings.TrimSpace(rule.Op))
	value := strings.TrimSpace(rule.Value)
	switch field {
	case "name":
		return compareString(node.Name, op, value)
	case "protocol":
		return compareString(node.Protocol, op, value)
	case "host":
		return compareString(node.Host, op, value)
	case "port":
		rulePort, err := strconv.Atoi(value)
		if err != nil {
			return true
		}
		return compareNumber(node.Port, op, rulePort)
	default:
		return true
	}
}

func compareString(left, op, right string) bool {
	l := strings.ToLower(strings.TrimSpace(left))
	r := strings.ToLower(strings.TrimSpace(right))
	switch op {
	case "contains":
		return strings.Contains(l, r)
	case "not_contains":
		return !strings.Contains(l, r)
	case "eq":
		return l == r
	case "ne":
		return l != r
	case "prefix":
		return strings.HasPrefix(l, r)
	case "suffix":
		return strings.HasSuffix(l, r)
	default:
		return true
	}
}

func compareNumber(left int, op string, right int) bool {
	switch op {
	case "eq":
		return left == right
	case "ne":
		return left != right
	case "gt":
		return left > right
	case "lt":
		return left < right
	case "ge":
		return left >= right
	case "le":
		return left <= right
	default:
		return true
	}
}

func asString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func asInt(value interface{}) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(v))
		return parsed
	default:
		return 0
	}
}

func fallbackString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
