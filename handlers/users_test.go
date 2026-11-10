package handlers

import (
	"encoding/json"
	"github.com/statping-ng/statping-ng/types/core"
	"github.com/statping-ng/statping-ng/types/notifications"
	"github.com/statping-ng/statping-ng/types/null"
	"github.com/statping-ng/statping-ng/types/services"
	"github.com/statping-ng/statping-ng/types/users"
	"github.com/statping-ng/statping-ng/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestUnAuthenticatedUserRoutes(t *testing.T) {
	tests := []HTTPTest{
		{
			Name:           "No Authentication - New User",
			URL:            "/api/users",
			Method:         "POST",
			ExpectedStatus: 401,
			BeforeTest:     UnsetTestENV,
		},
		{
			Name:           "No Authentication - Update User",
			URL:            "/api/users/1",
			Method:         "POST",
			ExpectedStatus: 401,
			BeforeTest:     UnsetTestENV,
		},
		{
			Name:           "No Authentication - View User",
			URL:            "/api/users/1",
			Method:         "GET",
			ExpectedStatus: 401,
			BeforeTest:     UnsetTestENV,
		},
		{
			Name:           "No Authentication - Delete User",
			URL:            "/api/users/1",
			Method:         "DELETE",
			ExpectedStatus: 401,
			BeforeTest:     UnsetTestENV,
		},
	}

	for _, v := range tests {
		t.Run(v.Name, func(t *testing.T) {
			str, t, err := RunHTTPTest(v, t)
			t.Logf("Test %s: \n %v\n", v.Name, str)
			assert.Nil(t, err)
		})
	}
}

func TestApiUsersRoutes(t *testing.T) {
	form := url.Values{}
	form.Add("username", "adminupdated")
	form.Add("password", "password12345")

	badForm := url.Values{}
	badForm.Add("username", "adminupdated")
	badForm.Add("password", "wrongpassword")

	tests := []HTTPTest{
		{
			Name:           "Check Basic Authentication",
			URL:            "/api",
			Method:         "GET",
			ExpectedStatus: 401,
			BeforeTest: func(t *testing.T) error {
				utils.Params.Set("AUTH_USERNAME", "admin")
				utils.Params.Set("AUTH_PASSWORD", "admin")
				return nil
			},
			AfterTest: func(t *testing.T) error {
				utils.Params.Set("AUTH_USERNAME", "")
				utils.Params.Set("AUTH_PASSWORD", "")
				return nil
			},
		},
		{
			Name:           "Statping All Users",
			URL:            "/api/users",
			Method:         "GET",
			ExpectedStatus: 200,
			ResponseLen:    1,
			BeforeTest:     SetTestENV,
		}, {
			Name:        "Statping Create User",
			URL:         "/api/users",
			HttpHeaders: []string{"Content-Type=application/json"},
			Method:      "POST",
			Body: `{
					"username": "adminuser2",
					"email": "info@adminemail.com",
					"password": "passsword123",
					"admin": true
				}`,
			ExpectedStatus:   200,
			ExpectedContains: []string{Success, MethodCreate},
		}, {
			Name:           "Statping View User",
			URL:            "/api/users/1",
			Method:         "GET",
			ExpectedStatus: 200,
		}, {
			Name:           "Statping Incorrect User ID",
			URL:            "/api/users/NOinteger",
			Method:         "GET",
			ExpectedStatus: 422,
		}, {
			Name:           "Statping Missing User",
			URL:            "/api/users/9393939393",
			Method:         "GET",
			ExpectedStatus: 404,
		}, {
			Name:   "Statping Update User",
			URL:    "/api/users/1",
			Method: "POST",
			Body: `{
					"username": "adminupdated",
					"email": "info@email.com",
					"password": "password12345",
					"admin": true
				}`,
			ExpectedStatus:   200,
			ExpectedContains: []string{Success, MethodUpdate},
		}, {
			Name:             "Statping Delete User",
			URL:              "/api/users/2",
			Method:           "DELETE",
			ExpectedStatus:   200,
			ExpectedContains: []string{Success, MethodDelete},
		}, {
			Name:             "Statping Login User",
			URL:              "/api/login",
			Method:           "POST",
			Body:             form.Encode(),
			ExpectedContains: []string{`"token"`},
			ExpectedStatus:   200,
			HttpHeaders:      []string{"Content-Type=application/x-www-form-urlencoded"},
		}, {
			Name:             "Statping Bad Login User",
			URL:              "/api/login",
			Method:           "POST",
			Body:             badForm.Encode(),
			ExpectedContains: []string{`incorrect authentication`},
			ExpectedStatus:   200,
			HttpHeaders:      []string{"Content-Type=application/x-www-form-urlencoded"},
		}, {
			Name:           "Statping Logout",
			URL:            "/api/logout",
			Method:         "GET",
			ExpectedStatus: 200,
		}, {
			Name:             "Incorrect JSON POST",
			URL:              "/api/users",
			Body:             BadJSON,
			ExpectedContains: []string{BadJSONResponse},
			BeforeTest:       SetTestENV,
			Method:           "POST",
			ExpectedStatus:   422,
		},
	}

	for _, v := range tests {
		t.Run(v.Name, func(t *testing.T) {
			_, t, err := RunHTTPTest(v, t)
			require.Nil(t, err)
		})
	}
}

// TestApiKeyAndSecretFieldsScope checks that the user list, the notifiers and the checkins
// are not readable anonymously, that their secrets are only returned to admins, and that
// the API key of a non-admin user does not grant admin access.
// It runs after TestApiUsersRoutes, which relies on the ids of the users it creates.
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

	slack := services.ReturnNotifier("slack")
	require.NotNil(t, slack)
	slackNotification := slack.Select()
	originalLogs := slackNotification.Logs
	slackNotification.Logs = append(slackNotification.Logs, &notifications.NotificationLog{Message: "seeded notifier log"})
	t.Cleanup(func() { slackNotification.Logs = originalLogs })

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
	notifierObjects := func(body string) []map[string]interface{} {
		var objects []map[string]interface{}
		require.Nil(t, json.Unmarshal([]byte(body), &objects))
		require.NotEmpty(t, objects)
		return objects
	}

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

	t.Run("Non-admin user - notifiers without credentials and logs", func(t *testing.T) {
		status, body := request("/api/notifiers", withReaderCookie)
		assert.Equal(t, http.StatusOK, status)
		assert.NotContains(t, body, "seeded notifier log")
		for _, notifier := range notifierObjects(body) {
			for _, field := range []string{"host", "port", "username", "password", "var1", "var2", "api_key", "api_secret", "success_data", "failure_data", "logs"} {
				assert.NotContains(t, notifier, field, "notifier %v", notifier["method"])
			}
		}
	})

	t.Run("API secret - notifiers with logs", func(t *testing.T) {
		status, body := request("/api/notifiers", withSecretHeader)
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, "seeded notifier log")
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
