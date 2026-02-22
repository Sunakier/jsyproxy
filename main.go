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
	subscribeHandler, err := handlers.NewSubscribeHandler(cfg)
	if err != nil {
		log.Fatalf("初始化订阅处理器失败: %v", err)
	}
	subscribeHandler.StartAutoRefresh()

	// 设置路由
	router.GET("/apix/getSubscribe", subscribeHandler.GetSubscribe)
	router.GET("/admin", subscribeHandler.AdminPage)
	router.POST("/admin/api/login", subscribeHandler.AdminLogin)

	adminAuth := middleware.AdminAuth(subscribeHandler.ValidateAdminSession)
	adminAPI := router.Group("/admin/api", adminAuth)
	{
		adminAPI.POST("/logout", subscribeHandler.AdminLogout)
		adminAPI.GET("/status", subscribeHandler.AdminStatus)
		adminAPI.GET("/cache-status", subscribeHandler.AdminCacheStatus)
		adminAPI.GET("/settings", subscribeHandler.AdminGetSettings)
		adminAPI.PUT("/settings", subscribeHandler.AdminUpdateSettings)
		adminAPI.POST("/refresh", subscribeHandler.AdminManualRefresh)

		adminAPI.GET("/upstreams", subscribeHandler.AdminListUpstreams)
		adminAPI.POST("/upstreams", subscribeHandler.AdminAddUpstream)
		adminAPI.PUT("/upstreams/:id", subscribeHandler.AdminUpdateUpstream)
		adminAPI.DELETE("/upstreams/:id", subscribeHandler.AdminDeleteUpstream)
		adminAPI.POST("/upstreams/:id/refresh", subscribeHandler.AdminRefreshUpstream)
		adminAPI.POST("/upstreams/:id/dedupe", subscribeHandler.AdminDedupeUpstreamCache)
		adminAPI.DELETE("/upstreams/:id/ua-cache", subscribeHandler.AdminDeleteUpstreamUACache)

		adminAPI.GET("/keys", subscribeHandler.AdminListKeys)
		adminAPI.POST("/keys", subscribeHandler.AdminAddKey)
		adminAPI.PUT("/keys/:id", subscribeHandler.AdminUpdateKey)
		adminAPI.DELETE("/keys/:id", subscribeHandler.AdminDeleteKey)

		adminAPI.GET("/logs", subscribeHandler.AdminGetLogs)
	}

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
