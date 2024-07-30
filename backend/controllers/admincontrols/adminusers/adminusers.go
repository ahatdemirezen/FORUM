package admincontrolusers

import (
	"encoding/json"
	"net/http"

	"forum/backend/controllers/structs"
	"forum/backend/database"
)

func AdminUsersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "ERROR: Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	db, errDb := database.OpenDb(w)
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, Email, UserName, Role FROM USERS")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []structs.User

	for rows.Next() {
		var user structs.User
		err = rows.Scan(&user.ID, &user.Email, &user.UserName, &user.Role)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}
	err = rows.Err()
	if err != nil {
		http.Error(w, "ERROR: Row iteration error", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(users)
	if err != nil {
		http.Error(w, "ERROR: Failed to encode posts to JSON", http.StatusInternalServerError)
		return
	}
}
