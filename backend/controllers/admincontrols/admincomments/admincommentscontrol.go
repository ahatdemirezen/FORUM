package admincommentscontrol

import (
	"encoding/json"
	"net/http"

	"forum/backend/controllers/structs"
	"forum/backend/database"
)

func AdminCommentsHandler(w http.ResponseWriter, r *http.Request) {
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
	commentRows, err := db.Query("SELECT ID, PostId, UserId, Comment, UserName, LikeCount FROM COMMENTS")
	if err != nil {
		http.Error(w, "ERROR: Query error for comments", http.StatusBadRequest)
		return
	}
	defer commentRows.Close()
	var comments []structs.Comment

	for commentRows.Next() {
		var comment structs.Comment
		err := commentRows.Scan(&comment.ID, &comment.PostId, &comment.UserId, &comment.Comment, &comment.UserName, &comment.LikeCount)
		if err != nil {
			http.Error(w, "ERROR: Database scan error", http.StatusBadRequest)
			return
		}
		comments = append(comments, comment)
	}

	err = commentRows.Err()
	if err != nil {
		http.Error(w, "ERROR: Comment Row iteration error", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(comments)
	if err != nil {
		http.Error(w, "ERROR: Failed to encode posts to JSON", http.StatusInternalServerError)
		return
	}
}
