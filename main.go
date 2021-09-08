package main

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	casURL          = "https://passport.ustc.edu.cn/login"
	validateBaseURL = "https://passport.ustc.edu.cn/serviceValidate"
	redirectURL     = "http://home.ustc.edu.cn/~kasper/cas/redirect.html"
)

func main() {
	e := echo.New()
	e.Use(middleware.Logger(), middleware.AddTrailingSlash(), AuthMiddleware)
	e.GET("/login", Login)
	e.Logger.Error(e.Start(":7777"))
}

func Login(c echo.Context) error {

	return c.NoContent(http.StatusOK)
}

func checkTicket(ticket, service string) ([]byte, error) {
	validateURL := fmt.Sprintf("%s?ticket=%s&service=%s", validateBaseURL, ticket, service)
	resp, err := http.Get(validateURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func regExp(reg string, data []byte) string {
	r := regexp.MustCompile(reg)
	s := r.FindSubmatch(data)
	return string(s[len(s)-1])
}

func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		_, err := c.Cookie("user")
		if err == nil {
			return next(c)
		}
		scheme := "http://"
		if c.IsTLS() {
			scheme = "https://"
		}
		jump := strings.Join([]string{scheme, c.Request().Host, c.Path()}, "")
		service := fmt.Sprintf("%s?jump=%s", redirectURL, jump)
		ticket := c.QueryParams().Get("ticket")
		if ticket == "" {
			return c.Redirect(http.StatusSeeOther, fmt.Sprintf("%s?service=%s", casURL, service))
		}

		data, err := checkTicket(ticket, service)
		if err != nil {
			return c.String(http.StatusUnauthorized, "unauthorized, please close browser and retry")
		}
		if !strings.Contains(string(data), "authenticationSuccess") {
			return c.String(http.StatusUnauthorized, "unauthorized, please close browser and retry")
		}
		user := regExp("<cas:user>(\\w+)</cas:user>", data)
		gid := regExp("<cas:gid>(\\d+)</cas:gid>", data)
		c.SetCookie(&http.Cookie{
			Name:    "user",
			Value:   user,
			Expires: time.Now().Add(time.Hour * 6),
		})
		c.SetCookie(&http.Cookie{
			Name:    "gid",
			Value:   gid,
			Expires: time.Now().Add(time.Hour * 6),
		})
		return next(c)
	}
}
