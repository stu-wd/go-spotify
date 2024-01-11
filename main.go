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
	frontendURI = "http://localhost:5151/dashboard"
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

	fmt.Println("Starting server GIZZ....")

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

    // Now you have the access token, you can use it to make requests to the Spotify API
    // (e.g., retrieve user data, playlists, etc.)

    fmt.Println("token =>", accessToken)

	redirectURL := fmt.Sprintf("%s?access_token=%s", frontendURI, accessToken)

	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
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


// import (
// 	"crypto/rand"
// 	"crypto/sha256"
// 	"encoding/base64"
// 	"encoding/json"
// 	"fmt"
// 	"net/http"
// )

// const (
// 	clientID     = "11e5eed30dc64bf9beb4da71653ca058"
// 	clientSecret = "a6929a7d37304776b1730e182623c0d6"
// 	redirectURI   = "http://localhost:8888/callback"
// 	authEndpoint  = "https://accounts.spotify.com/authorize"
// 	tokenEndpoint = "https://accounts.spotify.com/api/token"
// )

// // StateMap holds the state and code verifier for each user
// var StateMap = make(map[string]string)

// func main() {
// 	http.HandleFunc("/login", loginHandler)
// 	http.HandleFunc("/callback", callbackHandler)

// 	fmt.Println("Starting server....")
// 	http.ListenAndServe(":8888", nil)
// }

// func loginHandler(w http.ResponseWriter, r *http.Request) {
// 	// Generate a random state and code verifier
// 	state := generateRandomString(16)
// 	codeVerifier := generateRandomString(64)

// 	// Calculate the code challenge
// 	codeChallenge := base64URLEncode(sha256.New().Sum([]byte(codeVerifier)))

// 	// Store the state and code verifier for later verification
// 	StateMap[state] = codeVerifier

// 	// Construct the Spotify authorization URL with the code challenge
// 	authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&scope=user-read-private user-read-email&redirect_uri=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
// 		authEndpoint, clientID, redirectURI, state, codeChallenge)

// 	// Respond with the authorization URL
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(map[string]string{"authorization_url": authURL})

// 	// w.Header().Set("Access-Control-Allow-Origin", "*")
// 	// w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
// 	// w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
// 	// http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
// }

// func callbackHandler(w http.ResponseWriter, r *http.Request) {
// 	// Extract the state and code from the callback request
// 	state := r.URL.Query().Get("state")
// 	code := r.URL.Query().Get("code")

// 	// Retrieve the stored code verifier for the given state
// 	codeVerifier, ok := StateMap[state]
// 	if !ok {
// 		http.Error(w, "Invalid state", http.StatusBadRequest)
// 		return
// 	}

// 	// Exchange the authorization code for an access token
// 	accessToken, err := exchangeCodeForToken(code, codeVerifier)
// 	if err != nil {
// 		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
// 		return
// 	}

// 	// Respond with the access token in JSON format
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(map[string]string{"access_token": accessToken})
// }

// // Helper functions for PKCE implementation
// // (Note: These should be implemented securely in a production environment)

// func generateRandomString(length int) string {
// 	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
// 	b := make([]byte, length)
// 	rand.Read(b)
// 	for i := range b {
// 		b[i] = charset[int(b[i])%len(charset)]
// 	}
// 	return string(b)
// }

// func base64URLEncode(data []byte) string {
// 	return base64.RawURLEncoding.EncodeToString(data)
// }

// func exchangeCodeForToken(code, codeVerifier string) (string, error) {
// 	// Implement the logic to make a POST request to the Spotify token endpoint
// 	// and exchange the authorization code for an access token
// 	// Example: use the `http.PostForm` function

// 	// Replace the following code with your actual implementation
// 	// and handle the response to extract the access token
// 	resp, err := http.PostForm(tokenEndpoint, map[string][]string{
// 		"grant_type":    {"authorization_code"},
// 		"code":          {code},
// 		"redirect_uri":  {redirectURI},
// 		"client_id":     {clientID},
// 		"code_verifier": {codeVerifier},
// 	})
// 	if err != nil {
// 		return "", err
// 	}
// 	defer resp.Body.Close()

// 	// Parse the response body to extract the access token
// 	var tokenResponse map[string]interface{}
// 	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
// 		return "", err
// 	}

// 	accessToken, ok := tokenResponse["access_token"].(string)
// 	if !ok {
// 		return "", fmt.Errorf("Access token not found in the response")
// 	}

// 	return accessToken, nil
// }
