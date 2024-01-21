package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v5"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/cron"
)

const (
	callbackURL  = "http://localhost:8090/callback"
	scope        = "user-read-private user-read-email user-top-read playlist-read-private playlist-read-collaborative"
	authEndpoint = "https://accounts.spotify.com/authorize"
	tokenEndpoint = "https://accounts.spotify.com/api/token"
	frontendURI = "http://localhost:5151/login"
)

type AuthorizationResponse struct {
	AuthorizationURL string `json:"authorizationURL"`
}

// TokenResponse represents the response structure containing access token and refresh token
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
}

var (
	clientID string
	clientSecret string
	id string
)

func init() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file")
	}
	clientID = os.Getenv("SPOTIFY_CLIENT_ID")
	clientSecret = os.Getenv("SPOTIFY_CLIENT_SECRET")
	id = os.Getenv("STUSER_RECORD_ID")
}
func main() {
    app := pocketbase.New()

    // serves static files from the provided public dir (if exists)
    app.OnBeforeServe().Add(func(e *core.ServeEvent) error {

        e.Router.GET("/*", apis.StaticDirectoryHandler(os.DirFS("./pb_public"), false))

		scheduler := cron.New()

		scheduler.MustAdd("getStuToken", "*/55 * * * *", func() {
			err := refreshStuTokenJob(app)
			if err != nil {
				fmt.Println("Error refreshing token: ", err)
			}
		})

		scheduler.Start()

		e.Router.GET("/setup", func(c echo.Context)error {
			authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&scope=%s&redirect_uri=%s",
				authEndpoint, clientID, scope, callbackURL)

			return c.Redirect(307, authURL)
		})

		e.Router.GET("/callback", func(c echo.Context) error {
			code := c.QueryParam("code")

			accessToken, err := exchangeStuCodeForToken(code, app)

			if err != nil {
				c.Error(err)
			}

			redirectURL := fmt.Sprintf("%s?access_token=%s", frontendURI, accessToken)

			return c.Redirect(307, redirectURL)
		})

        return nil
    })

    if err := app.Start(); err != nil {
        log.Fatal(err)
    }

}

func refreshStuTokenJob(app core.App) error {
	record, err := app.Dao().FindRecordById("stuser", id)

	if err != nil {
		return err
	}

	resp, err := http.PostForm(tokenEndpoint, url.Values{
		"grant_type": {"refresh_token"},
		"refresh_token": {record.GetString("refresh_token")},
		"client_id": {clientID},
		"client_secret": {clientSecret},
	})

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	var refreshTokenResponse RefreshTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&refreshTokenResponse); err != nil {
		return err
	}

	record.Set("access_token", refreshTokenResponse.AccessToken)

	if err := app.Dao().SaveRecord(record); err != nil {
		return err
	}

	return nil
}

func exchangeStuCodeForToken(code string, app core.App) (string, error) {
	resp, err := http.PostForm(tokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callbackURL},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()	

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", err
	}

	record, err := app.Dao().FindRecordById("stuser", id)

	if err != nil {
		return "", err
	}

	record.Set("access_token", tokenResponse.AccessToken)
	record.Set("refresh_token", tokenResponse.RefreshToken)

	if err := app.Dao().SaveRecord(record); err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
}
