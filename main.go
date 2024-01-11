package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

const (
	redirectURI  = "http://localhost:8888/callback"
	scope        = "user-read-private user-read-email user-top-read playlist-read-private playlist-read-collaborative"
	authEndpoint = "https://accounts.spotify.com/authorize"
	tokenEndpoint = "https://accounts.spotify.com/api/token"
	frontendURI = "http://localhost:5151/login"
)

type AuthorizationResponse struct {
	AuthorizationURL string `json:"authorizationURL"`
}

var (
	clientID string
	clientSecret string
)

func init() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file")
	}
	clientID = os.Getenv("SPOTIFY_CLIENT_ID")
	clientSecret = os.Getenv("SPOTIFY_CLIENT_SECRET")
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/setup", setupHandler).Methods("GET")

	// Handle the /callback route
	r.HandleFunc("/callback", callbackHandler).Methods("GET")

	// Handle the /health route
	r.HandleFunc("/health", healthHandler).Methods("GET")

	corsHandler := handlers.CORS(
		handlers.AllowedHeaders([]string{"Content-Type"}),
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		handlers.AllowedOrigins([]string{"*"}), // Adjust this according to your frontend's actual domain
	)

	http.Handle("/", corsHandler(r))

	fmt.Println("Starting server GIZZ....")

	// Start the server
	http.ListenAndServe(":8888", nil)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "API is live")
}

func setupHandler(w http.ResponseWriter, r *http.Request) {
	authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&scope=%s&redirect_uri=%s",
		authEndpoint, clientID, scope, redirectURI)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the authorization code from the query parameters
    code := r.URL.Query().Get("code")

    // Validate state if needed

    // Exchange the authorization code for an access token
    accessToken, err := exchangeStuCodeForToken(code)
    if err != nil {
        // Handle the error
        http.Error(w, "Failed to exchange code for token stu callback", http.StatusInternalServerError)
        return
    }

	redirectURL := fmt.Sprintf("%s?access_token=%s", frontendURI, accessToken)

	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func exchangeStuCodeForToken(code string) (string, error) {
    resp, err := http.PostForm(tokenEndpoint, url.Values{
        "grant_type":    {"authorization_code"},
        "code":          {code},
        "redirect_uri":  {redirectURI},
        "client_id":     {clientID},
        "client_secret": {clientSecret},
    })
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    // Parse the response body to extract the access token
    var tokenResponse map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
        return "", err
    }

    accessToken, ok := tokenResponse["access_token"].(string)
    if !ok {
        return "", fmt.Errorf("Access token not found in the response")
    }

    return accessToken, nil
}