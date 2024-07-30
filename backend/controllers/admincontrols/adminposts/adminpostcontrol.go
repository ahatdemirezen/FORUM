package adminpostcontrol

import (
	"encoding/json"
	"net/http"

	"forum/backend/controllers/structs"
	"forum/backend/database"
)

func AdminPostsHandler(w http.ResponseWriter, r *http.Request) {
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
	rows, err := db.Query("SELECT ID, UserID, UserName, Title, Content, LikeCount FROM POSTS")
	if err != nil {
		http.Error(w, "ERROR: Unable to fetch posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []structs.Post
	for rows.Next() {
		var post structs.Post
		err := rows.Scan(&post.ID, &post.UserID, &post.UserName, &post.Title, &post.Content, &post.LikeCount)
		if err != nil {
			http.Error(w, "ERROR: Unable to scan post", http.StatusInternalServerError)
			return
		}
		posts = append(posts, post)
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(posts)
	if err != nil {
		http.Error(w, "ERROR: Failed to encode posts to JSON", http.StatusInternalServerError)
		return
	}
}

