package handlers_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"jsyproxy/handlers"
	"jsyproxy/store"
)

func TestParseSubscriptionNodes(t *testing.T) {
	t.Parallel()

	t.Run("base64 encoded vmess link", func(t *testing.T) {
		t.Parallel()

		config := map[string]string{
			"v":    "2",
			"ps":   "VMess Test",
			"add":  "vmess.example.com",
			"port": "443",
			"id":   "11111111-1111-1111-1111-111111111111",
			"aid":  "0",
			"net":  "tcp",
			"tls":  "tls",
			"scy":  "auto",
		}
		payload, err := json.Marshal(config)
		if err != nil {
			t.Fatalf("json.Marshal returned error: %v", err)
		}
		line := "vmess://" + base64.StdEncoding.EncodeToString(payload)
		body := []byte(base64.StdEncoding.EncodeToString([]byte(line)))

		nodes, err := handlers.ParseSubscriptionNodes(body)
		if err != nil {
			t.Fatalf("ParseSubscriptionNodes returned error: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("ParseSubscriptionNodes returned %d nodes, want 1", len(nodes))
		}
		if nodes[0].Protocol != "vmess" {
			t.Errorf("Protocol = %q, want %q", nodes[0].Protocol, "vmess")
		}
		if nodes[0].Name != "VMess Test" {
			t.Errorf("Name = %q, want %q", nodes[0].Name, "VMess Test")
		}
		if nodes[0].Host != "vmess.example.com" {
			t.Errorf("Host = %q, want %q", nodes[0].Host, "vmess.example.com")
		}
		if nodes[0].Port != 443 {
			t.Errorf("Port = %d, want 443", nodes[0].Port)
		}
	})

	t.Run("plain vless link", func(t *testing.T) {
		t.Parallel()

		body := []byte("vless://11111111-1111-1111-1111-111111111111@vless.example.com:8443?encryption=none&security=tls&type=tcp#VLESS%20Node")
		nodes, err := handlers.ParseSubscriptionNodes(body)
		if err != nil {
			t.Fatalf("ParseSubscriptionNodes returned error: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("ParseSubscriptionNodes returned %d nodes, want 1", len(nodes))
		}
		if nodes[0].Protocol != "vless" {
			t.Errorf("Protocol = %q, want %q", nodes[0].Protocol, "vless")
		}
		if nodes[0].Name != "VLESS Node" {
			t.Errorf("Name = %q, want %q", nodes[0].Name, "VLESS Node")
		}
		if nodes[0].Host != "vless.example.com" {
			t.Errorf("Host = %q, want %q", nodes[0].Host, "vless.example.com")
		}
		if nodes[0].Port != 8443 {
			t.Errorf("Port = %d, want 8443", nodes[0].Port)
		}
	})

	t.Run("empty input returns error", func(t *testing.T) {
		t.Parallel()

		if _, err := handlers.ParseSubscriptionNodes([]byte(" \n\t ")); err == nil {
			t.Fatalf("ParseSubscriptionNodes returned nil error")
		}
	})

	t.Run("plain trojan link", func(t *testing.T) {
		t.Parallel()

		body := []byte("trojan://mypassword@trojan.example.com:443?sni=trojan.example.com#Trojan%20Node")
		nodes, err := handlers.ParseSubscriptionNodes(body)
		if err != nil {
			t.Fatalf("ParseSubscriptionNodes returned error: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("ParseSubscriptionNodes returned %d nodes, want 1", len(nodes))
		}
		if nodes[0].Protocol != "trojan" {
			t.Errorf("Protocol = %q, want %q", nodes[0].Protocol, "trojan")
		}
		if nodes[0].Name != "Trojan Node" {
			t.Errorf("Name = %q, want %q", nodes[0].Name, "Trojan Node")
		}
		if nodes[0].Host != "trojan.example.com" {
			t.Errorf("Host = %q, want %q", nodes[0].Host, "trojan.example.com")
		}
		if nodes[0].Port != 443 {
			t.Errorf("Port = %d, want 443", nodes[0].Port)
		}
	})

	t.Run("plain ss link", func(t *testing.T) {
		t.Parallel()

		userinfo := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:testpassword"))
		body := []byte("ss://" + strings.TrimRight(userinfo, "=") + "@ss.example.com:8388#SS%20Node")
		nodes, err := handlers.ParseSubscriptionNodes(body)
		if err != nil {
			t.Fatalf("ParseSubscriptionNodes returned error: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("ParseSubscriptionNodes returned %d nodes, want 1", len(nodes))
		}
		if nodes[0].Protocol != "ss" {
			t.Errorf("Protocol = %q, want %q", nodes[0].Protocol, "ss")
		}
		if nodes[0].Name != "SS Node" {
			t.Errorf("Name = %q, want %q", nodes[0].Name, "SS Node")
		}
		if nodes[0].Host != "ss.example.com" {
			t.Errorf("Host = %q, want %q", nodes[0].Host, "ss.example.com")
		}
		if nodes[0].Port != 8388 {
			t.Errorf("Port = %d, want 8388", nodes[0].Port)
		}
	})
}

func TestFilterNodesPatternHandling(t *testing.T) {
	t.Parallel()

	t.Run("plain pipe pattern is literal", func(t *testing.T) {
		t.Parallel()

		nodes := []handlers.MergedNode{
			{Name: "US Basic"},
			{Name: "Premium Node"},
			{Name: "US|Premium Node"},
		}
		filtered := handlers.FilterNodes(nodes, []string{"US|Premium"}, nil, nil)
		if len(filtered) != 1 {
			t.Fatalf("FilterNodes returned %d nodes, want 1", len(filtered))
		}
		if filtered[0].Name != "US|Premium Node" {
			t.Errorf("filtered[0].Name = %q, want %q", filtered[0].Name, "US|Premium Node")
		}
	})

	t.Run("re prefix pattern matches as regex", func(t *testing.T) {
		t.Parallel()

		nodes := []handlers.MergedNode{{Name: "US Premium"}, {Name: "HK Premium"}}
		filtered := handlers.FilterNodes(nodes, []string{"re:US.*"}, nil, nil)
		if len(filtered) != 1 {
			t.Fatalf("FilterNodes returned %d nodes, want 1", len(filtered))
		}
		if filtered[0].Name != "US Premium" {
			t.Errorf("filtered[0].Name = %q, want %q", filtered[0].Name, "US Premium")
		}
	})

	t.Run("slash delimited pattern matches as regex", func(t *testing.T) {
		t.Parallel()

		nodes := []handlers.MergedNode{{Name: "HK Standard"}, {Name: "TW Standard"}, {Name: "SG Standard"}}
		filtered := handlers.FilterNodes(nodes, []string{"/HK|TW/"}, nil, nil)
		if len(filtered) != 2 {
			t.Fatalf("FilterNodes returned %d nodes, want 2", len(filtered))
		}
		if filtered[0].Name != "HK Standard" || filtered[1].Name != "TW Standard" {
			t.Errorf("filtered names = %q, %q; want HK Standard, TW Standard", filtered[0].Name, filtered[1].Name)
		}
	})

	t.Run("long regex pattern is ignored as regex", func(t *testing.T) {
		t.Parallel()

		longPattern := "re:" + strings.Repeat("A", 201)
		nodes := []handlers.MergedNode{{Name: strings.Repeat("A", 201)}}
		filtered := handlers.FilterNodes(nodes, []string{longPattern}, nil, nil)
		if len(filtered) != 0 {
			t.Fatalf("FilterNodes returned %d nodes, want 0", len(filtered))
		}
	})

	t.Run("literal include and exclude", func(t *testing.T) {
		t.Parallel()

		nodes := []handlers.MergedNode{{Name: "US Standard"}, {Name: "US Blocked"}, {Name: "HK Standard"}}
		filtered := handlers.FilterNodes(nodes, []string{"US"}, []string{"Blocked"}, nil)
		if len(filtered) != 1 {
			t.Fatalf("FilterNodes returned %d nodes, want 1", len(filtered))
		}
		if filtered[0].Name != "US Standard" {
			t.Errorf("filtered[0].Name = %q, want %q", filtered[0].Name, "US Standard")
		}
	})
}

func TestDedupeMergedNodes(t *testing.T) {
	t.Parallel()

	nodes := []handlers.MergedNode{
		{Protocol: "VMESS", Name: "US One", Host: "example.com", Port: 443},
		{Protocol: "vmess", Name: "us one", Host: "example.com", Port: 443},
		{Protocol: "vmess", Name: "US Two", Host: "example.com", Port: 443},
	}
	filtered := handlers.DedupeMergedNodes(nodes)
	if len(filtered) != 2 {
		t.Fatalf("DedupeMergedNodes returned %d nodes, want 2", len(filtered))
	}
	if filtered[0].Name != "US One" {
		t.Errorf("filtered[0].Name = %q, want %q", filtered[0].Name, "US One")
	}
	if filtered[1].Name != "US Two" {
		t.Errorf("filtered[1].Name = %q, want %q", filtered[1].Name, "US Two")
	}
}

func TestApplyNameReplacements(t *testing.T) {
	t.Parallel()

	nodes := []handlers.MergedNode{{Name: "US Premium"}}
	replacements := []store.MergeNameReplacement{{From: "Premium", To: "Standard"}}
	replaced := handlers.ApplyNameReplacements(nodes, replacements)
	if len(replaced) != 1 {
		t.Fatalf("ApplyNameReplacements returned %d nodes, want 1", len(replaced))
	}
	if replaced[0].Name != "US Standard" {
		t.Errorf("replaced[0].Name = %q, want %q", replaced[0].Name, "US Standard")
	}
}
