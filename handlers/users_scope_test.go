package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/statping-ng/statping-ng/types/core"
	"github.com/statping-ng/statping-ng/types/null"
	"github.com/statping-ng/statping-ng/types/users"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApiKeyAndSecretFieldsScope checks that the user list, the notifiers and the checkins
// are not readable anonymously, that their secrets are only returned to admins, and that
// the API key of a non-admin user does not grant admin access.
func TestApiKeyAndSecretFieldsScope(t *testing.T) {
	UnsetTestENV(t)
	t.Cleanup(func() { SetTestENV(t) })

	admin := &users.User{
		Username: "scopeadmin",
		Email:    "scopeadmin@email.com",
		Password: "password123",
		Admin:    null.NewNullBool(true),
	}
	require.Nil(t, admin.Create())
	t.Cleanup(func() { admin.Delete() })

	reader := &users.User{
		Username: "scopereader",
		Email:    "scopereader@email.com",
		Password: "password123",
		Admin:    null.NewNullBool(false),
	}
	require.Nil(t, reader.Create())
	t.Cleanup(func() { reader.Delete() })

	require.NotEmpty(t, admin.ApiKey)
	require.NotEmpty(t, reader.ApiKey)

	router := Router()
	_, readerToken := setJwtToken(reader, httptest.NewRecorder())

	request := func(url string, configure func(r *http.Request)) (int, string) {
		req, err := http.NewRequest("GET", url, nil)
		require.Nil(t, err)
		if configure != nil {
			configure(req)
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr.Result().StatusCode, rr.Body.String()
	}
	withSecretHeader := func(r *http.Request) { r.Header.Set("Authorization", core.App.ApiSecret) }
	withReaderCookie := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: cookieName, Value: readerToken}) }

	for _, url := range []string{"/api/users", "/api/notifiers", "/api/checkins"} {
		t.Run("No Authentication - "+url, func(t *testing.T) {
			status, body := request(url, nil)
			assert.Equal(t, http.StatusUnauthorized, status)
			assert.NotContains(t, body, admin.ApiKey)
		})
		t.Run("Non-admin API key - "+url, func(t *testing.T) {
			status, body := request(url+"?api="+reader.ApiKey, nil)
			assert.Equal(t, http.StatusUnauthorized, status)
			assert.NotContains(t, body, admin.ApiKey)
		})
	}

	t.Run("API secret - users with secrets", func(t *testing.T) {
		status, body := request("/api/users", withSecretHeader)
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, admin.ApiKey)
		assert.Contains(t, body, `"password"`)
	})

	t.Run("Admin API key - users with secrets", func(t *testing.T) {
		status, body := request("/api/users?api="+admin.ApiKey, nil)
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, reader.ApiKey)
	})

	t.Run("Non-admin user - users without secrets", func(t *testing.T) {
		status, body := request("/api/users", withReaderCookie)
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, `"scopeadmin"`)
		assert.NotContains(t, body, admin.ApiKey)
		assert.NotContains(t, body, reader.ApiKey)
		assert.NotContains(t, body, `"password"`)
	})

	t.Run("Non-admin user - notifiers without credentials", func(t *testing.T) {
		status, body := request("/api/notifiers", withReaderCookie)
		assert.Equal(t, http.StatusOK, status)
		for _, field := range []string{`"host"`, `"username"`, `"password"`, `"var1"`, `"var2"`, `"api_key"`, `"api_secret"`} {
			assert.NotContains(t, body, field)
		}
	})

	t.Run("Non-admin API key - admin route", func(t *testing.T) {
		status, _ := request("/api/logs?api="+reader.ApiKey, nil)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("Admin API key - admin route", func(t *testing.T) {
		status, _ := request("/api/logs?api="+admin.ApiKey, nil)
		assert.Equal(t, http.StatusOK, status)
	})
}
