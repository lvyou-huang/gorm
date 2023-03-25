package middleware

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"gorm/model"
	"net/http"
	"strings"
	"time"
)

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		token, err := jwt.ParseWithClaims(tokenString, &model.Custom_claims{}, func(t *jwt.Token) (interface{}, error) { return model.JwtKey, nil })

		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": -1, "msg": fmt.Sprintf("access token parse error: %v", err)})
			return
		}

		if claims, ok := token.Claims.(*model.Custom_claims); ok && token.Valid {
			if !claims.VerifyExpiresAt(time.Now(), false) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": -1, "msg": "access token expired"})
				return
			}
			// 3. 可以直接操作calims结构，如: claims.Username claims.Isadmin，这里是gin中间件，存放到ctx中，供处理函数使用
			c.Set("claims", claims)
		} else {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": -1, "msg": fmt.Sprintf("Claims parse error: %v", err)})
			return
		}
		c.Next()

	}
}
