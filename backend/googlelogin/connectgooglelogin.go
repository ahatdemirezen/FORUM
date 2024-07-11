package googlelogin

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"forum/backend/database"
	"forum/backend/readenv"
	"forum/backend/requests"

	"github.com/gofrs/uuid"
)

func GoogleLoginHandler(w http.ResponseWriter, r *http.Request) {
	state := "login-" + uuid.Must(uuid.NewV4()).String()
	url := fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&state=%s&scope=openid email&response_type=code&prompt=select_account",
		readenv.GoogleClientID,
		url.QueryEscape("http://localhost:8080/google/callback"),
		state,
	)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func GoogleRegisterHandler(w http.ResponseWriter, r *http.Request) {
	state := "register-" + uuid.Must(uuid.NewV4()).String()
	url := fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&state=%s&scope=openid email&response_type=code&prompt=select_account",
		readenv.GoogleClientID,
		url.QueryEscape("http://localhost:8080/google/callback"),
		state,
	)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Println("Failed to parse form:", err)
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	state := r.FormValue("state")
	if state == "" {
		log.Println("Invalid state")
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		log.Println("Invalid code")
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}

	token, err := requests.GetGoogleAccessToken(code)
	if err != nil {
		log.Println("Failed to get access token:", err)
		http.Error(w, fmt.Sprintf("Failed to get access token: %v", err), http.StatusInternalServerError)
		return
	}

	user, err := requests.GetGoogleUser(token)
	if err != nil {
		log.Println("Failed to get user info:", err)
		http.Error(w, fmt.Sprintf("Failed to get user info: %v", err), http.StatusInternalServerError)
		return
	}

	db, errDb := database.OpenDb(w)
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()
	var userID int
	err = db.QueryRow("SELECT ID FROM USERS WHERE Email = ?", user.Email).Scan(&userID)
	if err == sql.ErrNoRows {
		_, err = db.Exec("INSERT INTO USERS (Email, UserName, Password, Role, session_token) VALUES (?, ?, ?, ?, ?)", user.Email, user.Name, "", "User", "")
		if err != nil {
			log.Println("Error creating user:", err)
			http.Error(w, "Error creating user", http.StatusInternalServerError)
			return
		}
		err = db.QueryRow("SELECT ID FROM USERS WHERE Email = ?", user.Email).Scan(&userID)
		if err != nil {
			log.Println("Error retrieving user ID:", err)
			http.Error(w, "Error retrieving user ID", http.StatusInternalServerError)
			return
		}
	} else if err != nil {
		log.Println("Error retrieving user ID:", err)
		http.Error(w, "Error retrieving user ID", http.StatusInternalServerError)
		return
	}

	sessionToken, err := uuid.NewV4()
	if err != nil {
		log.Println("Error generating session token:", err)
		http.Error(w, "Error generating session token", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("UPDATE USERS SET session_token = ? WHERE ID = ?", sessionToken.String(), userID)
	if err != nil {
		log.Println("Error updating session token:", err)
		http.Error(w, "Error updating session token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken.String(),
		Expires:  time.Now().Add(24 * time.Hour),
		Path:     "/",
		HttpOnly: true,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
