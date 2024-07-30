package adminmoderators

import (
	"net/http"

	"forum/backend/requests"
)

func AdminModeratorPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "ERROR: Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	action := r.FormValue("action")
	userID := r.FormValue("user_id")

	err := requests.GetModeratorFromAdmins("http://localhost:8080/api/moderators", userID, action)
	if err != nil {
		http.Error(w, "ERROR: Bad request", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}
