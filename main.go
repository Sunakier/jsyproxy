package main

import (
	"jsyproxy/config"
	"jsyproxy/handlers"
	"jsyproxy/middleware"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	// 加载配置
	cfg := config.Load()
	log.Printf("服务器启动，监听端口: %s", cfg.Port)

	// 设置Gin模式为发布模式
	gin.SetMode(gin.ReleaseMode)

	// 创建Gin路由器
	router := gin.New()

	// 添加日志中间件
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// 创建订阅处理器
	subscribeHandler := handlers.NewSubscribeHandler(cfg)

	// 设置路由
	// 只允许 /apix/getSubscribe 接口访问，其他返回403
	router.GET("/apix/getSubscribe", middleware.TokenAuth(cfg.Token), subscribeHandler.GetSubscribe)

	// 处理所有其他路由，返回403
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "访问被拒绝",
		})
	})

	// 启动服务器
	if err := router.Run(":" + cfg.Port); err != nil {
		log.Fatalf("启动服务器失败: %v", err)
	}
}
