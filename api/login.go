package api

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm/middleware"
	"gorm/model"
	"log"
	"net/http"
	"time"
)

var JwtKey = []byte("secret")

func Api() {
	router := gin.Default()
	router.LoadHTMLGlob("templates/*")
	router.Static("static", "./static")

	dsn := "root:admin@tcp(127.0.0.1:3306)/dataframe?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Println(err)
		return
	}
	router.POST("/login", func(c *gin.Context) {
		data, _ := c.GetRawData()
		var m map[string]string
		_ = json.Unmarshal(data, &m)

		phoneoremail := m["phoneoremail"]
		password := m["password"]
		user := model.User{}
		result := db.First(&user, "phoneoremail=? and password=?", phoneoremail, password)
		if result.Error != nil {
			log.Println(result.Error)
			return
		}
		claims := model.Custom_claims{
			Phoneoremail: phoneoremail,
			Isadmin:      true,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: &jwt.NumericDate{time.Now().Add(1 * time.Hour)},
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		if tokenString, err := token.SignedString(model.JwtKey); err != nil {
			c.JSON(http.StatusOK, gin.H{"code": -1, "msg": "generate access token failed: " + err.Error()})
		} else {
			c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "", "data": tokenString})
		}

	})
	router.GET("/home", middleware.AuthRequired(), func(c *gin.Context) {
		c.HTML(200, "home3.html", gin.H{})
	})

	router.Run()
}
