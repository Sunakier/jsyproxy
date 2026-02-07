package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
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
func AdminAuth(validateSession func(string) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := c.GetHeader("X-Admin-Session")
		if session == "" {
			if cookie, err := c.Cookie("admin_session"); err == nil {
				session = cookie
			}
		}

		if !validateSession(session) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "未登录或登录已过期",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
