package adminpost

import (
	"fmt"
	"html/template"
	"net/http"

	"forum/backend/requests"
)

func PostPageForAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "ERROR: Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	data, errReq := requests.GetDataForPostInAdminRole("http://localhost:8080/api/adminposts")
	if errReq != nil {
		http.Error(w, "ERROR: Bad request123", http.StatusBadRequest)
		fmt.Println("hata")
		return
	}

	tmpl, err := template.ParseFiles("frontend/pages/admincontrol/adminpost/adminpostpage.html")
	if err != nil {
		http.Error(w, "ERROR: Unable to parse template", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "ERROR: Unable to execute template", http.StatusInternalServerError)
		return
	}
}

func DeletePostPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "ERROR: Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	postID := r.FormValue("post_id")

	err := requests.DeletePostForAdmin("http://localhost:8080/api/admindeletepost", postID)
	if err != nil {
		http.Error(w, "ERROR: Bad request", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin/posts", http.StatusSeeOther)
}
