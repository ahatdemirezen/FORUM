package createpostpage

import (
	"net/http"

	"forum/backend/requests"
)

const createPostApiUrl = "http://localhost:8080/api/createpost"

func CreatePostPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		http.ServeFile(w, r, "frontend/pages/createPostPage/createPostPage.html")
	case "POST":
		cookie, cookieErr := r.Cookie("session_token")
		if cookieErr != nil {
			http.Error(w, "ERROR: You are not authorized to create post", http.StatusUnauthorized)
			return
		}
		title := r.FormValue("title")
		content := r.FormValue("content")
		categoryDatas := GetCategoryDatas(r)

		err := requests.CreatePostRequest(createPostApiUrl, title, content, categoryDatas, cookie.Value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		http.Redirect(w, r, "/myposts", http.StatusSeeOther)
	}
}

func GetCategoryDatas(r *http.Request) map[string]string {
	categories := []string{"go", "html", "css", "php", "python", "c", "cpp", "csharp", "js", "assembly", "react", "flutter", "rust"}
	categoryDatas := make(map[string]string)

	for _, category := range categories {
		if r.FormValue(category) == "true" {
			categoryDatas[category] = "true"
		} else {
			categoryDatas[category] = "false"
		}
	}
	return categoryDatas
}
