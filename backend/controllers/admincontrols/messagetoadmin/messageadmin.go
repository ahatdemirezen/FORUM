package messagetoadmin

import (
	"fmt"
	"net/http"

	"forum/backend/database"
)

func HandlerGetMessageForAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "ERROR: Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	username := r.FormValue("username")
	email := r.FormValue("email")
	explanation := r.FormValue("explanation")

	db, errDb := database.OpenDb(w)
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()

	_, err := db.Exec(`INSERT INTO ModeratorRequests (username, email, explanation) VALUES (?, ?, ?)`, username, email, explanation)
	if err != nil {
		http.Error(w, "ERROR: Failed to insert data", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Succesfully Sent")
}
