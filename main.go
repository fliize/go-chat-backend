// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"gopkg.in/ini.v1"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var jwt_secret = []byte("hahaha12efew")

type User struct {
	gorm.Model
	Username string
	Password string
}

var user User
var users []User

var addr = flag.String("addr", "127.0.0.1:8080", "http service address")

func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method               //请求方法
		origin := c.Request.Header.Get("Origin") //请求头部
		var headerKeys []string                  // 声明请求头keys
		for k, _ := range c.Request.Header {
			headerKeys = append(headerKeys, k)
		}
		headerStr := strings.Join(headerKeys, ", ")
		if headerStr != "" {
			headerStr = fmt.Sprintf("access-control-allow-origin, access-control-allow-headers, %s", headerStr)
		} else {
			headerStr = "access-control-allow-origin, access-control-allow-headers"
		}
		if origin != "" {
			origin := c.Request.Header.Get("Origin")
			c.Header("Access-Control-Allow-Origin", origin)                                    // 这是允许访问所有域
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE,UPDATE") //服务器支持的所有跨域请求的方法,为了避免浏览次请求的多次'预检'请求
			//  header的类型
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Length, X-CSRF-Token, Token,session,X_Requested_With,Accept, Origin, Host, Connection, Accept-Encoding, Accept-Language,DNT, X-CustomHeader, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Content-Type, Pragma")
			//              允许跨域设置                                                                                                      可以返回其他子段
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers,Cache-Control,Content-Language,Content-Type,Expires,Last-Modified,Pragma,FooBar") // 跨域关键设置 让浏览器可以解析
			c.Header("Access-Control-Max-Age", "172800")                                                                                                                                                           // 缓存请求信息 单位为秒
			c.Header("Access-Control-Allow-Credentials", "false")                                                                                                                                                  //  跨域请求是否需要带cookie信息 默认设置为true
			c.Set("content-type", "application/json")                                                                                                                                                              // 设置返回格式是json
		}

		//放行所有OPTIONS方法
		if method == "OPTIONS" {
			c.JSON(http.StatusOK, "Options Request!")
		}
		// 处理请求
		c.Next() //  处理请求
	}
}

func validate_token(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return jwt_secret, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		ID := claims["ID"]
		dsn := "root:@tcp(127.0.0.1:3306)/go_chat?charset=utf8mb4&parseTime=True&loc=Local"
		db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			log.Fatal("连接数据库失败", err)
		}
		user := User{}
		res := db.Table("user_list").Find(&user, ID)
		if res.RowsAffected > 0 {
			return true
		}
		return false
	} else {
		fmt.Println(err)
		return false
	}
}

func get_id(tokenString string) (int, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return jwt_secret, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return int(claims["ID"].(float64)), nil
	} else {
		fmt.Println(err)
		return -1, err
	}
}

func main() {
	flag.Parse()
	hub := newHub()
	go hub.run()
	go func() {
		http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query()["token"]
			log.Println("token:", token)
			log.Println("token[0]:", token[0])
			if len(token) == 0 {
				return
			}
			log.Println("?????????????")
			valid := validate_token(token[0])
			if valid {
				serveWs(hub, w, r)
			} else {
				return
			}
		})
		err := http.ListenAndServe(*addr, nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}()

	r := gin.Default()
	r.Use(Cors())
	cfg, err := ini.Load("config.ini")
	if err != nil {
		fmt.Println("文件读取错误", err)
		os.Exit(1)
	}
	mysqlConfig := cfg.Section("mysql")
	dsn := mysqlConfig.Key("User").Value() + mysqlConfig.Key("Password").Value() + "@tcp(" + mysqlConfig.Key("Host").Value() + ")/" + mysqlConfig.Key("Name").Value() + "?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	r.GET("/user", func(c *gin.Context) {
		if err != nil {
			panic("failed to connect database")
		}
		users := []User{}
		db.Table("user_list").Select("username").Limit(2).Find(&users)
		println(users)
		c.JSON(http.StatusOK, gin.H{
			"message": users,
		})
	})
	r.POST("/login", func(ctx *gin.Context) {

		json := make(map[string]interface{})
		ctx.BindJSON(&json)
		username := json["username"]
		password := json["password"]
		log.Println("username:", username, "password:", password)
		user := User{}
		res := db.Table("user_list").Where("username = ? AND password = ?", username, password).First(&user)
		log.Println("user:", user)
		if res.RowsAffected > 0 {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"ID":  user.ID,
				"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
			})

			// Sign and get the complete encoded token as a string using the secret
			tokenString, err := token.SignedString(jwt_secret)
			log.Println("tokenString:", tokenString, "err:", err)
			if err != nil {
				log.Println("err:", err)
				ctx.JSON(http.StatusOK, gin.H{
					"code":    401,
					"message": "登陆失败",
				})
			} else {
				ctx.JSON(http.StatusOK, gin.H{
					"code":    0,
					"message": tokenString,
				})
			}
		} else {
			ctx.JSON(http.StatusOK, gin.H{
				"code":    401,
				"message": "登陆失败",
			})
		}
	})
	r.GET("/getFriendList", func(ctx *gin.Context) {
		token := ctx.Request.Header.Get("token")
		log.Println("qwqqwqw111111qwq")
		id, err := get_id(token)
		log.Println("qwqqwqwqwq")
		if err != nil {
			ctx.JSON(http.StatusOK, gin.H{
				"code":    401,
				"message": "鉴权失败",
			})
		}
		type Result struct {
			Username string
		}
		var Results []Result
		db.Table("user_list").Select("Username").Where("id in (?)", db.Table("user_relation").Select("friend_id").Where("user_id = ?", id)).Scan(&Results)
		log.Println("users:", Results)
		ctx.JSON(http.StatusOK, gin.H{
			"code":    0,
			"message": Results,
		})
	})
	r.Run("127.0.0.1:8081")
}
