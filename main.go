package main

import (
	"jsyproxy/config"
	"jsyproxy/handlers"
	"jsyproxy/middleware"
	"jsyproxy/store"
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

	adminAuth := middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission)
	adminAPI := router.Group("/admin/api", adminAuth)
	{
		adminAPI.POST("/logout", subscribeHandler.AdminLogout)
		adminAPI.GET("/status", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionAdminRead), subscribeHandler.AdminStatus)
		adminAPI.GET("/cache-status", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUpstreamRead), subscribeHandler.AdminCacheStatus)
		adminAPI.GET("/settings", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionAdminRead), subscribeHandler.AdminGetSettings)
		adminAPI.PUT("/settings", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionSettingsWrite), subscribeHandler.AdminUpdateSettings)
		adminAPI.GET("/settings/ua-rules/export", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionAdminRead), subscribeHandler.AdminExportUARules)
		adminAPI.POST("/settings/ua-rules/import", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionSettingsWrite), subscribeHandler.AdminImportUARules)
		adminAPI.POST("/refresh", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionAdminWrite), subscribeHandler.AdminManualRefresh)

		adminAPI.GET("/upstreams", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUpstreamRead), subscribeHandler.AdminListUpstreams)
		adminAPI.POST("/upstreams", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUpstreamWrite), subscribeHandler.AdminAddUpstream)
		adminAPI.PUT("/upstreams/:id", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUpstreamWrite), subscribeHandler.AdminUpdateUpstream)
		adminAPI.DELETE("/upstreams/:id", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUpstreamWrite), subscribeHandler.AdminDeleteUpstream)
		adminAPI.POST("/upstreams/:id/refresh", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUpstreamWrite), subscribeHandler.AdminRefreshUpstream)
		adminAPI.GET("/upstreams/:id/node-status", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUpstreamRead), subscribeHandler.AdminGetUpstreamNodeStatus)
		adminAPI.POST("/upstreams/:id/node-status/refresh", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUpstreamWrite), subscribeHandler.AdminRefreshUpstreamNodeStatus)
		adminAPI.POST("/upstreams/:id/dedupe", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUpstreamWrite), subscribeHandler.AdminDedupeUpstreamCache)
		adminAPI.DELETE("/upstreams/:id/ua-cache", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUpstreamWrite), subscribeHandler.AdminDeleteUpstreamUACache)

		adminAPI.GET("/keys", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionKeyRead), subscribeHandler.AdminListKeys)
		adminAPI.POST("/keys", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionKeyWrite), subscribeHandler.AdminAddKey)
		adminAPI.PUT("/keys/:id", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionKeyWrite), subscribeHandler.AdminUpdateKey)
		adminAPI.DELETE("/keys/:id", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionKeyWrite), subscribeHandler.AdminDeleteKey)

		adminAPI.GET("/users", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUserManage), subscribeHandler.AdminListUsers)
		adminAPI.POST("/users", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUserManage), subscribeHandler.AdminAddUser)
		adminAPI.PUT("/users/:id", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUserManage), subscribeHandler.AdminUpdateUser)
		adminAPI.PUT("/users/:id/password", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUserManage), subscribeHandler.AdminUpdateUserPassword)
		adminAPI.DELETE("/users/:id", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionUserManage), subscribeHandler.AdminDeleteUser)

		adminAPI.GET("/logs", middleware.AdminAuth(subscribeHandler.ValidateAdminSession, subscribeHandler.HasPermission, store.PermissionLogRead), subscribeHandler.AdminGetLogs)
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
