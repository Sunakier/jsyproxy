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
