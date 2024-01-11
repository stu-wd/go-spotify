package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

const (
	clientID     = "11e5eed30dc64bf9beb4da71653ca058"
	clientSecret = "a6929a7d37304776b1730e182623c0d6"
	redirectURI  = "http://localhost:8888/callback"
	scope        = "user-read-private user-read-email"
	authEndpoint = "https://accounts.spotify.com/authorize"
	tokenEndpoint = "https://accounts.spotify.com/api/token"
)

func main() {
	r := mux.NewRouter()


	r.HandleFunc("/setup", setupHandler).Methods("GET")

	// Handle the /login route
	r.HandleFunc("/login", loginHandler).Methods("GET")

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

	fmt.Println("Starting server....")

	// Start the server
	http.ListenAndServe(":8888", nil)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "API is live")
}

func setupHandler(w http.ResponseWriter, r *http.Request) {
	// Redirect the user to Spotify authorization endpoint
	authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&scope=%s&redirect_uri=%s",
		authEndpoint, clientID, scope, redirectURI)

	// Respond with the authorization URL
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}


func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Redirect the user to Spotify authorization endpoint
	authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&scope=%s&redirect_uri=%s",
		authEndpoint, clientID, scope, redirectURI)

		//    w.Header().Set("Access-Control-Allow-Origin", "*")
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
    accessToken, err := exchangeCodeForToken(code)
    if err != nil {
        // Handle the error
        http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
        return
    }

	fmt.Println("token =>", accessToken)

    // Now you have the access token, you can use it to make requests to the Spotify API
    // (e.g., retrieve user data, playlists, etc.)

    fmt.Fprint(w, "Callback received! Code: %s, Access Token: %s", code, accessToken)
}

func exchangeCodeForToken(code string) (string, error) {
    // Implement the logic to make a POST request to the Spotify token endpoint
    // and exchange the authorization code for an access token
    // Example: use the `http.PostForm` function

    // Replace the following code with your actual implementation
    // and handle the response to extract the access token
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

