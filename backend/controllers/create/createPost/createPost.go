package createpost

import (
	"fmt"
	"net/http"

	"forum/backend/auth"
	"forum/backend/database"
)

func CreatePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "ERROR: Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	title := r.FormValue("title")
	content := r.FormValue("content")

	if !IsForumPostValid(title, content) {
		http.Error(w, "ERROR: Content or title cannot empty", http.StatusBadRequest)
		return
	}

	db, errDb := database.OpenDb(w)
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()

	authenticated, userId, userName := auth.IsAuthenticated(r, db)
	if !authenticated {
		http.Error(w, "ERROR: You are not authorized to create post", http.StatusUnauthorized)
		return
	}

	result, errEx := db.Exec(`INSERT INTO POSTS (UserID, UserName, Title, Content) VALUES (?, ?, ?, ?)`, userId, userName, title, content)
	if errEx != nil {
		http.Error(w, "ERROR: Post did not added into the database", http.StatusBadRequest)
		return
	}

	postID, err := result.LastInsertId()
	if err != nil {
		http.Error(w, "ERROR: Could not retrieve post ID", http.StatusBadRequest)
		return
	}

	categoryValues := GetCategoryValues(r)
	_, err = db.Exec(`INSERT INTO CATEGORIES (USERID, PostID, GO, HTML, CSS, PHP, PYTHON, C, "CPP", "CSHARP", JS, ASSEMBLY, REACT, FLUTTER, RUST) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userId, postID, categoryValues["go"], categoryValues["html"], categoryValues["css"], categoryValues["php"],
		categoryValues["python"], categoryValues["c"], categoryValues["cpp"], categoryValues["csharp"],
		categoryValues["js"], categoryValues["assembly"], categoryValues["react"], categoryValues["flutter"], categoryValues["rust"])
	if err != nil {
		http.Error(w, "ERROR: Could not add categories to the database", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Post successfully created")
}

func IsForumPostValid(title, content string) bool {
	return title != "" && content != ""
}

func GetCategoryValues(r *http.Request) map[string]int {
	categories := []string{"go", "html", "css", "php", "python", "c", "cpp", "csharp", "js", "assembly", "react", "flutter", "rust"}
	categoryValues := make(map[string]int)

	for _, category := range categories {
		if r.FormValue(category) == "true" {
			categoryValues[category] = 1
		} else {
			categoryValues[category] = 0
		}
	}
	return categoryValues
}
