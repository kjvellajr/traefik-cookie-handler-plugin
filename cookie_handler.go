// Package traefik_cookie_handler_plugin Traefik Cookie Handler Plugin.
package traefik_cookie_handler_plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Config the plugin configuration.
type Config struct {
	Url             string   `json:"url,omitempty"`
	Method          string   `json:"method,omitempty"`
	Body            string   `json:"body,omitempty"`
	ResponseCookies []string `json:"responseCookies,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// CookieHandler a Cookie Handler plugin.
type CookieHandler struct {
	next            http.Handler
	name            string
	url             string
	body            string
	method          string
	responseCookies []string
}

// New creates a new Cookie Handler plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	if config.Url == "" {
		return nil, fmt.Errorf("URL cannot be empty")
	}
	// TODO validate url

	if config.Method == "" {
		return nil, fmt.Errorf("method cannot be empty")
	}
	// TODO validate method

	if len(config.ResponseCookies) == 0 {
		return nil, fmt.Errorf("responseCookies cannot be empty")
	}
	// TODO check if any cookie contains whitespaces or other invalid characters

	return &CookieHandler{
		next:            next,
		name:            name,
		url:             config.Url,
		body:            config.Body,
		method:          config.Method,
		responseCookies: config.ResponseCookies,
	}, nil
}

func (middleware *CookieHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	if req.Header.Get("X-CookieHandler-Request") != "" {
		// skip if this is a cookie handler request
		middleware.next.ServeHTTP(rw, req)
		return
	}

	if middleware.hasAllCookies(req) {
		// skip if we already have all the cookies set
		middleware.next.ServeHTTP(rw, req)
		return
	}

	cookieHandlerResp, err := middleware.invokeCookieHandler(rw, req)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	upstreamCookie := req.Header.Get("Cookie")
	for _, responseCookie  := range middleware.responseCookies {
		cookie, err := getCookie(cookieHandlerResp.Cookies(), responseCookie)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}

		// set Set-Cookie on response for client
		http.SetCookie(rw, cookie)

		// build upstream Cookie header
		upstreamCookie = upstreamCookie + ";" + cookie.Name + "=" + cookie.Value
	}


	req.Header.Set("Cookie", upstreamCookie)

	middleware.next.ServeHTTP(rw, req)
}

func (middleware *CookieHandler) invokeCookieHandler(rw http.ResponseWriter, req *http.Request) (*http.Response, error) {

	parsedUrl, err := url.Parse(strings.TrimSpace(middleware.url))
	if err != nil {
		return nil, err
	}

	var reqBody io.Reader = nil
	if middleware.body != "" {
		reqBody = strings.NewReader(middleware.body)
	}

	mediumReq, err := http.NewRequest(middleware.method, parsedUrl.String(), reqBody)
	if err != nil {
		return nil, err
	}

	mediumReq.Header.Set("Cookie", req.Header.Get("Cookie"))
	mediumReq.Header.Set("X-CookieHandler-Request", "true")

	client := &http.Client{}

	resp, err := client.Do(mediumReq)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func getCookie(cookies []*http.Cookie, name string) (*http.Cookie, error) {

	if cookies == nil {
		return &http.Cookie{}, fmt.Errorf("No cookies")
	}
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie, nil
		}
	}
	return &http.Cookie{}, fmt.Errorf("Cookie %s not found", name)
}

func (middleware *CookieHandler) hasAllCookies(req *http.Request) bool {

	for _, responseCookie  := range middleware.responseCookies {
		_, err := req.Cookie(responseCookie)
		if err != nil {
			switch {
			case errors.Is(err, http.ErrNoCookie):
				// missing cookie
				return false
			default:
				// error getting cookie
				return false
			}
		}
	}
	return true
}
