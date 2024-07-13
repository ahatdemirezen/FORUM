package requests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"forum/backend/auth"
	"forum/backend/controllers/structs"
	"forum/backend/database"
	"forum/backend/readenv"
)

func GetDataForServe(apiURL string) ([]structs.Post, error) {
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var posts []structs.Post
	if err := json.NewDecoder(resp.Body).Decode(&posts); err != nil {
		return nil, err
	}

	return posts, nil
}

func GetDataForServeWithReq(apiURL string, cookieValue string) ([]structs.Post, error) {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return nil, err
	}

	req.AddCookie(&http.Cookie{Name: "session_token", Value: cookieValue})

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return nil, nil
	}
	defer resp.Body.Close()

	var posts []structs.Post
	if err := json.NewDecoder(resp.Body).Decode(&posts); err != nil {
		return nil, err
	}

	return posts, nil
}

func GetCommentDataForServeWithReq(apiURL string, cookieValue string) ([]structs.Comment, error) {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return nil, err
	}

	req.AddCookie(&http.Cookie{Name: "session_token", Value: cookieValue})

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return nil, nil
	}
	defer resp.Body.Close()

	var posts []structs.Comment
	if err := json.NewDecoder(resp.Body).Decode(&posts); err != nil {
		return nil, err
	}

	return posts, nil
}

func GetPostWithComments(apiURL string, postId string) (structs.PostWithComments, error) {
	req, err := http.NewRequest("GET", apiURL+"?id="+postId, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return structs.PostWithComments{}, err
	}

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return structs.PostWithComments{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return structs.PostWithComments{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var data structs.PostWithComments
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return structs.PostWithComments{}, err
	}

	return data, nil
}

func GetSearchedDataForServeWithReq(apiURL string, filter string, category string, search string) ([]structs.Post, error) {
	req, err := http.NewRequest("GET", apiURL+"?filter="+filter+"&category="+category+"&search="+search, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return nil, err
	}

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return nil, nil
	}
	defer resp.Body.Close()

	var posts []structs.Post
	if err := json.NewDecoder(resp.Body).Decode(&posts); err != nil {
		return nil, err
	}

	return posts, nil
}

func RegisterRequest(apiURL string, email string, userName string, password string) error {
	formData := url.Values{}
	formData.Set("email", email)
	formData.Set("username", userName)
	formData.Set("password", password)

	encodedFormData := formData.Encode()

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(encodedFormData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		return fmt.Errorf(bodyString)
	}

	return nil
}

func LoginRequest(apiURL string, email string, password string, w http.ResponseWriter) error {
	formData := url.Values{}
	formData.Set("email", email)
	formData.Set("password", password)

	encodedFormData := formData.Encode()

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(encodedFormData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		return fmt.Errorf(bodyString)
	}

	db, errDb := database.OpenDb(w)
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		return errDb
	}
	defer db.Close()

	sessionToken, errToken := auth.CreateSessionToken()
	if errToken != nil {
		http.Error(w, "ERROR: Internal Server Error", http.StatusInternalServerError)
		return errToken
	}

	var userID int
	errQue := db.QueryRow("SELECT ID FROM USERS WHERE Email = ?", email).Scan(&userID)
	if errQue != nil {
		http.Error(w, "ERROR: Invalid email", http.StatusBadRequest)
		return err
	}

	errSetToken := auth.SetTokenInDatabase(w, db, sessionToken, userID)
	if errSetToken != nil {
		http.Error(w, "ERROR: Internal Server Error", http.StatusInternalServerError)
		return errSetToken
	}

	auth.SetCookie(w, sessionToken)

	return nil
}

func CreatePostRequest(apiURL string, title string, photo io.Reader, photoFilename, content string, categoryDatas map[string]string, cookieValue string) error {
	// Multipart form oluşturma
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// Title ve content alanlarını ekleme
	writer.WriteField("title", title)
	writer.WriteField("content", content)

	// Fotoğraf dosyasını ekleme
	if photo != nil {
		part, err := writer.CreateFormFile("photo", photoFilename)
		if err != nil {
			return fmt.Errorf("error creating form file: %v", err)
		}
		_, err = io.Copy(part, photo)
		if err != nil {
			return fmt.Errorf("error copying photo file: %v", err)
		}
	}

	// Kategorileri ekleme
	for key, val := range categoryDatas {
		writer.WriteField(key, val)
	}

	// Writer'ı kapatma
	err := writer.Close()
	if err != nil {
		return fmt.Errorf("error closing writer: %v", err)
	}

	// HTTP isteği oluşturma
	req, err := http.NewRequest("POST", apiURL, &body)
	if err != nil {
		return err
	}

	// Cookie ekleme
	req.AddCookie(&http.Cookie{Name: "session_token", Value: cookieValue})

	// Content-Type header'ını ayarlama
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// İstek gönderme
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		return fmt.Errorf(bodyString)
	}

	return nil
}

func CreateCommentRequest(apiURL string, postId string, comment string, cookieValue string) error {
	formData := url.Values{}
	formData.Set("id", postId)
	formData.Set("comment", comment)

	encodedFormData := formData.Encode()

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(encodedFormData))
	if err != nil {
		return err
	}

	req.AddCookie(&http.Cookie{Name: "session_token", Value: cookieValue})

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		return fmt.Errorf(bodyString)
	}

	return nil
}

func VoteRequest(apiURL string, id string, isComment string, postId string, cookieValue string) error {
	formData := url.Values{}
	formData.Set("id", id)
	formData.Set("isComment", isComment)
	formData.Set("post_id", postId)

	encodedFormData := formData.Encode()

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(encodedFormData))
	if err != nil {
		return err
	}

	req.AddCookie(&http.Cookie{Name: "session_token", Value: cookieValue})

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		return fmt.Errorf(bodyString)
	}

	return nil
}

func DeleteAccountRequest(apiURL string, password string, cookieValue string) error {
	formData := url.Values{}
	formData.Set("password", password)

	encodedFormData := formData.Encode()

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(encodedFormData))
	if err != nil {
		return err
	}

	req.AddCookie(&http.Cookie{Name: "session_token", Value: cookieValue})

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		return fmt.Errorf(bodyString)
	}

	return nil
}

func DeletePostRequest(apiURL string, postId string, cookieValue string) error {
	formData := url.Values{}
	formData.Set("id", postId)

	encodedFormData := formData.Encode()

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(encodedFormData))
	if err != nil {
		return err
	}

	req.AddCookie(&http.Cookie{Name: "session_token", Value: cookieValue})

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		return fmt.Errorf(bodyString)
	}

	return nil
}

func DeleteCommentRequest(apiURL string, commentId string, cookieValue string) error {
	formData := url.Values{}
	formData.Set("id", commentId)

	encodedFormData := formData.Encode()

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(encodedFormData))
	if err != nil {
		return err
	}

	req.AddCookie(&http.Cookie{Name: "session_token", Value: cookieValue})

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		return fmt.Errorf(bodyString)
	}

	return nil
}

func GetGoogleAccessToken(code string) (string, error) {
	values := url.Values{}
	values.Set("client_id", readenv.GoogleClientID)
	values.Set("client_secret", readenv.GoogleClientSecret)
	values.Set("code", code)
	values.Set("redirect_uri", "http://localhost:8080/google/callback")
	values.Set("grant_type", "authorization_code")

	resp, err := http.Post("https://oauth2.googleapis.com/token", "application/x-www-form-urlencoded", strings.NewReader(values.Encode()))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	return result["access_token"].(string), nil
}

type GoogleUser struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	ID    string `json:"id"`
}

func GetGoogleUser(token string) (GoogleUser, error) {
	var user GoogleUser

	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("failed to get user info: %s", resp.Status)
	}

	err = json.NewDecoder(resp.Body).Decode(&user)
	return user, err
}

func GetFacebookAccessToken(code string) (string, error) {
	values := url.Values{}
	values.Set("client_id", readenv.FacebookClientID)
	values.Set("client_secret", readenv.FacebookClientSecret)
	values.Set("code", code)
	values.Set("redirect_uri", "http://localhost:8080/facebook/callback")

	resp, err := http.PostForm("https://graph.facebook.com/v10.0/oauth/access_token", values)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	token, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("no access token found in response")
	}

	return token, nil
}

type FacebookUser struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	ID    string `json:"id"`
}

func GetFacebookUser(token string) (FacebookUser, error) {
	var user FacebookUser

	req, err := http.NewRequest("GET", "https://graph.facebook.com/me?fields=id,name,email", nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("failed to get user info: %s", resp.Status)
	}

	err = json.NewDecoder(resp.Body).Decode(&user)
	return user, err
}

func GetGithubAccessToken(code string) (string, error) {
	values := url.Values{}
	values.Set("client_id", readenv.GithubClientID)
	values.Set("client_secret", readenv.GithubClientSecret)
	values.Set("code", code)
	values.Set("redirect_uri", "http://localhost:8080/github/callback")

	resp, err := http.Post("https://github.com/login/oauth/access_token", "application/x-www-form-urlencoded", strings.NewReader(values.Encode()))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Parse response
	query, err := url.ParseQuery(string(body))
	if err != nil {
		return "", err
	}

	return query.Get("access_token"), nil
}

type GitHubUser struct {
	Login string `json:"login"`
	Email string `json:"email"`
	Name  string `json:"name"`
	ID    int    `json:"id"`
}

// getGithubUser fetches the GitHub user information using the provided token
func GetGithubUser(token string) (GitHubUser, error) {
	var user GitHubUser

	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "token "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("failed to get user info: %s", resp.Status)
	}

	err = json.NewDecoder(resp.Body).Decode(&user)
	return user, err
}
