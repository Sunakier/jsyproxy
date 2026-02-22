package config

import (
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	Port                   string
	AdminUsername          string
	AdminPassword          string
	DataFile               string
	DefaultRefreshInterval string
	BootstrapAccessKeys    []string
}

func Load() *Config {
	// 尝试加载 .env 文件，如果不存在也不报错
	_ = godotenv.Load() // 忽略错误，优先使用环境变量

	config := &Config{
		Port:                   getEnv("PORT", "3000"),
		AdminUsername:          getEnv("ADMIN_USERNAME", "admin"),
		AdminPassword:          getEnv("ADMIN_PASSWORD", ""),
		DataFile:               getEnv("DATA_FILE", "data/state.json"),
		DefaultRefreshInterval: getEnv("DEFAULT_REFRESH_INTERVAL", "10m"),
	}
	config.BootstrapAccessKeys = parseCSV(getEnv("ACCESS_KEYS", ""))

	if config.AdminPassword == "" {
		log.Fatal("ADMIN_PASSWORD 环境变量是必需的，请设置后重新启动")
	}

	log.Printf("配置加载完成 - 端口: %s, BootstrapAccessKeys数量: %d, 默认刷新周期: %s", config.Port, len(config.BootstrapAccessKeys), config.DefaultRefreshInterval)
	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{})
	for _, item := range parts {
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
