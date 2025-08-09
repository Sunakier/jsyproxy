package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Port          string
	Token         string
	UpstreamURL   string
	Authorization string
	UserAgent     string
	Host          string
	Origin        string
	Referer       string
}

func Load() *Config {
	// 尝试加载 .env 文件，如果不存在也不报错
	_ = godotenv.Load() // 忽略错误，优先使用环境变量

	config := &Config{
		Port:          getEnv("PORT", "3000"),
		Token:         getEnv("TOKEN", "PKenOMF2rAwf1df"),
		UpstreamURL:   getEnv("UPSTREAM_URL", "https://api.ajin168.com/api/v1/user/getSubscribe"),
		Authorization: getEnv("AUTHORIZATION", ""),
		UserAgent:     getEnv("USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"),
		Host:          getEnv("HOST", "api.ajin168.com"),
		Origin:        getEnv("ORIGIN", "https://w4.rouhe88.com"),
		Referer:       getEnv("REFERER", "https://w4.rouhe88.com/"),
	}

	// 验证必需的配置
	if config.Authorization == "" {
		log.Fatal("AUTHORIZATION 环境变量是必需的，请设置后重新启动")
	}

	log.Printf("配置加载完成 - 端口: %s, 上游URL: %s", config.Port, config.UpstreamURL)
	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
