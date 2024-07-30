package adminusers

import (
	"html/template"
	"net/http"

	"forum/backend/requests"
)

func UsersPageForAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "ERROR: Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	data, errReq := requests.GetDataForUsersInAdminRole("http://localhost:8080/api/adminusers")
	if errReq != nil {
		http.Error(w, "ERROR: Bad request", http.StatusBadRequest)
		return
	}
	tmpl, err := template.ParseFiles("frontend/pages/admincontrol/adminusers/adminusers.html")
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
