package admincomments

import (
	"html/template"
	"net/http"

	"forum/backend/requests"
)

func CommentsPageForAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "ERROR: Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	data, errReq := requests.GetDataForCommentsInAdminRole("http://localhost:8080/api/admincomments")
	if errReq != nil {
		http.Error(w, "ERROR: Bad request", http.StatusBadRequest)
		return
	}
	tmpl, err := template.ParseFiles("frontend/pages/admincontrol/admincomments/admincommentspage.html")
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

func DeleteCommentsPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "ERROR: Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	commentID := r.FormValue("comment_id")
	err := requests.DeleteCommentsForAdmin("http://localhost:8080/api/admindeletecomments", commentID)
	if err != nil {
		http.Error(w, "ERROR: Bad request", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin/comments", http.StatusSeeOther)
}
