package adminmoderatorcontrol

import (
	"encoding/json"
	"net/http"

	"forum/backend/controllers/structs"
	"forum/backend/database"
)

func AdminModeratorsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "ERROR: Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	action := r.FormValue("action")
	userID := r.FormValue("user_id")

	db, errDb := database.OpenDb(w)
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()

	var newRole string
	if action == "promote" {
		newRole = "moderator"
	} else if action == "demote" {
		newRole = "user"
	} else {
		http.Error(w, "ERROR: Invalid action", http.StatusBadRequest)
		return
	}
	_, err := db.Exec("UPDATE USERS SET Role = ? WHERE id = ?", newRole, userID)
	if err != nil {
		http.Error(w, "ERROR: Unable to update user role", http.StatusInternalServerError)
		return
	}
	var updatedUser structs.User
	err = db.QueryRow("SELECT id, Email, UserName, Role FROM USERS WHERE id = ?", userID).Scan(&updatedUser.ID, &updatedUser.Email, &updatedUser.UserName, &updatedUser.Role)
	if err != nil {
		http.Error(w, "ERROR: Unable to fetch updated user", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(updatedUser)
	if err != nil {
		http.Error(w, "ERROR: Failed to encode user to JSON", http.StatusInternalServerError)
		return
	}
}
