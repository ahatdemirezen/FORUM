package login

import (
	"fmt"
	"net/http"

	"forum/backend/database"

	"golang.org/x/crypto/bcrypt"
)

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "ERROR: Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if !AreLoginCredentialsCorrect(email, password) {
		http.Error(w, "ERROR: Please provide the login credentials correct", http.StatusBadRequest)
		return
	}

	db, errDb := database.OpenDb(w)
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()

	var storedPassword string
	var userID int
	err := db.QueryRow("SELECT ID, Password FROM USERS WHERE Email = ?", email).Scan(&userID, &storedPassword)
	if err != nil {
		http.Error(w, "ERROR: Invalid email", http.StatusBadRequest)
		return
	}

	errComparePasswd := ArePasswordsMatching(storedPassword, password)
	if errComparePasswd != nil {
		http.Error(w, "ERROR: Invalid password", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User successfully logged in")
}

func ArePasswordsMatching(storedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		return err
	}
	return nil
}

func AreLoginCredentialsCorrect(email, password string) bool {
	return email != "" && password != ""
}
