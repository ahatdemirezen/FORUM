package admindeletecontrol

import (
	"fmt"
	"net/http"

	"forum/backend/database"
)

func DeletePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "ERROR: Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	postID := r.FormValue("post_id")

	db, errDb := database.OpenDb(w)
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()

	_, err := db.Exec("DELETE FROM POSTS WHERE ID = ?", postID)
	if err != nil {
		http.Error(w, "ERROR: Unable to delete post", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Post successfully deleted")
}
