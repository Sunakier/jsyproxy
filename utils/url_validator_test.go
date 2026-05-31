package utils

import "testing"

func TestValidateOutboundURLRejectsPrivateAndReservedIPs(t *testing.T) {
	t.Parallel()

	tests := []string{
		"http://127.0.0.1",
		"http://10.0.0.1",
		"http://172.16.0.1",
		"http://192.168.1.1",
		"http://169.254.169.254",
		"http://0.0.0.0",
		"http://[::1]",
		"http://[::ffff:127.0.0.1]",
	}

	for _, rawURL := range tests {
		rawURL := rawURL
		t.Run(rawURL, func(t *testing.T) {
			t.Parallel()
			if err := ValidateOutboundURL(rawURL, false); err == nil {
				t.Fatalf("ValidateOutboundURL(%q, false) returned nil", rawURL)
			}
		})
	}
}

func TestValidateOutboundURLRejectsUnsupportedSchemes(t *testing.T) {
	t.Parallel()

	tests := []string{
		"file:///etc/passwd",
		"ftp://internal",
		"gopher://127.0.0.1",
	}

	for _, rawURL := range tests {
		rawURL := rawURL
		t.Run(rawURL, func(t *testing.T) {
			t.Parallel()
			if err := ValidateOutboundURL(rawURL, false); err == nil {
				t.Fatalf("ValidateOutboundURL(%q, false) returned nil", rawURL)
			}
		})
	}
}

func TestValidateOutboundURLAllowsPublicTargets(t *testing.T) {
	t.Parallel()

	tests := []string{
		"https://example.com",
		"https://1.1.1.1",
		"http://8.8.8.8",
	}

	for _, rawURL := range tests {
		rawURL := rawURL
		t.Run(rawURL, func(t *testing.T) {
			t.Parallel()
			if err := ValidateOutboundURL(rawURL, false); err != nil {
				t.Fatalf("ValidateOutboundURL(%q, false) returned error: %v", rawURL, err)
			}
		})
	}
}

func TestValidateOutboundURLAllowsPrivateTargetsWhenConfigured(t *testing.T) {
	t.Parallel()

	if err := ValidateOutboundURL("http://127.0.0.1", true); err != nil {
		t.Fatalf("ValidateOutboundURL with allowPrivate=true returned error: %v", err)
	}
}

func TestValidateOutboundURLRejectsEmptyAndMalformedURLs(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		"http://[::1",
	}

	for _, rawURL := range tests {
		rawURL := rawURL
		t.Run(rawURL, func(t *testing.T) {
			t.Parallel()
			if err := ValidateOutboundURL(rawURL, false); err == nil {
				t.Fatalf("ValidateOutboundURL(%q, false) returned nil", rawURL)
			}
		})
	}
}
