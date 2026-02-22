package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	ContextAdminUserID   = "admin_user_id"
	ContextAdminUsername = "admin_username"
	ContextAdminRole     = "admin_role"
)

// TokenAuth 创建Token鉴权中间件
func TokenAuth(validToken string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Query("token")

		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "缺少token参数",
			})
			c.Abort()
			return
		}

		if token != validToken {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "无效的token",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// AdminAuth 创建后台登录鉴权中间件
func AdminAuth(
	validateSession func(string) (string, string, string, bool),
	hasPermission func(string, string, string) bool,
	requiredPermissions ...string,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := c.GetHeader("X-Admin-Session")
		if session == "" {
			if cookie, err := c.Cookie("admin_session"); err == nil {
				session = cookie
			}
		}

		userID, username, role, ok := validateSession(session)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "未登录或登录已过期",
			})
			c.Abort()
			return
		}

		for _, permission := range requiredPermissions {
			if !hasPermission(userID, role, permission) {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "权限不足",
				})
				c.Abort()
				return
			}
		}

		c.Set(ContextAdminUserID, userID)
		c.Set(ContextAdminUsername, username)
		c.Set(ContextAdminRole, role)

		c.Next()
	}
}
