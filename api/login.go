package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	casURL          = "https://passport.ustc.edu.cn/login"
	validateBaseURL = "https://passport.ustc.edu.cn/serviceValidate"
	redirectURL     = "http://home.ustc.edu.cn/~kasper/cas/redirect.html"
)

func Login(w http.ResponseWriter, req *http.Request) {
	jump := fmt.Sprintf("https://%s%s", req.Host, req.URL.Path)
	service := fmt.Sprintf("%s?jump=%s", redirectURL, jump)
	ticket := req.URL.Query().Get("ticket")
	if ticket == "" {
		http.Redirect(w, req, fmt.Sprintf("%s?service=%s", casURL, service), http.StatusSeeOther)
		return
	}
	data, err := checkTicket(ticket, service)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	dataStr := string(data)
	if !strings.Contains(dataStr, "authenticationSuccess") {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	_, _ = w.Write(data)
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
