package traefik_cookie_handler_plugin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cookieHandler "github.com/kjvellajr/traefik-cookie-handler-plugin"
)

func TestCookieHandler(t *testing.T) {
	cfg := cookieHandler.CreateConfig()
	cfg.Url = "https://my-api.my-domain.com"
	cfg.Body = "{\"username\":\"foo\",\"password\",\"bar\"}"
	cfg.Method = http.MethodGet
	cfg.ResponseCookies = []string{"JWT-SESSION", "XSRF-TOKEN"}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	plugin, err := cookieHandler.New(ctx, next, cfg, "cookie-handler-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, cfg.Method, cfg.Url, strings.NewReader(cfg.Body))
	if err != nil {
		t.Fatal(err)
	}

	plugin.ServeHTTP(recorder, req)
}
