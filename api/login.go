package api

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

const (
	casURL          = "https://passport.ustc.edu.cn/login"
	validateBaseURL = "https://passport.ustc.edu.cn/serviceValidate"
	redirectURL     = "http://home.ustc.edu.cn/~kasper/cas/redirect.html"
)

func Login(w http.ResponseWriter, req *http.Request) {
	scheme := "http://"
	if req.TLS != nil {
		scheme = "https://"
	}
	jump := strings.Join([]string{scheme, req.Host, req.URL.Path}, "")
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
	if !strings.Contains(string(data), "authenticationSuccess") {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	user := regExp("<cas:user>(\\w+)</cas:user>", data)
	gid := regExp("<cas:gid>(\\d+)</cas:gid>", data)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(user + "\n" + gid))
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
