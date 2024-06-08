package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const port = ":8080"

func main() {
	loadEnv()

	defer db.Close()

	http.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))
	// Statik dosyaları servis etme
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Ana sayfayı ele alan fonksiyon
	http.HandleFunc("/", MainPageHandler)

	// Ana sayfayı ele alan fonksiyon
	http.HandleFunc("/post", PostPageHandler)

	// Yeni üye sayfasını ele alan fonksiyon
	http.HandleFunc("/register", RegisterHandler)
	http.HandleFunc("/login/google", handleGoogleLogin)
	http.HandleFunc("/callback/google", handleGoogleCallback)
	http.HandleFunc("/login/github", handleGitHubLogin)
	http.HandleFunc("/callback/github", handleGitHubCallback)

	// Üye giriş sayfasını ele alan fonksiyon
	http.HandleFunc("/login", LoginHandler)

	http.HandleFunc("/createpost", CreatePost)

	http.HandleFunc("/logout", LogoutHandler)

	http.HandleFunc("/deletepost", DeletePost)

	http.HandleFunc("/deletecomment", DeleteComment)

	http.HandleFunc("/like", LikePostHandler)
	http.HandleFunc("/dislike", DislikePostHandler)
	http.HandleFunc("/addreply", AddReplyHandler)

	http.HandleFunc("/mycomments", MyCommentsHandler)
	http.HandleFunc("/myposts", MyPostsHandler)
	http.HandleFunc("/likedposts", LikedPostsHandler)

	http.HandleFunc("/deleteaccount", DeleteAccountHandler)

	fmt.Printf("Server is running on %s", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		panic(err)
	}
}

var db *sql.DB

var (
	googleClientID     string
	googleClientSecret string
	githubClientID     string
	githubClientSecret string
)

func loadEnv() {
	file, err := os.Open(".env")
	if err != nil {
		log.Fatalf("Error opening .env file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := parts[1]
		os.Setenv(key, value)
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading .env file: %v", err)
	}

	googleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	githubClientID = os.Getenv("GITHUB_CLIENT_ID")
	githubClientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
}

type Post struct {
	UserName  string
	UserID    int
	Title     string
	Content   string
	ID        int
	LikeCount int
	PhotoPath string
}

type Reply struct {
	ID        int
	CommentID int
	UserID    int
	Reply     string
	CreatedAt time.Time
}

type Comment struct {
	ID        int
	UserName  string
	Comment   string
	LikeCount int
	Replies   []Reply
}

type PostWithComments struct {
	Post     Post
	Comments []Comment
}

// Ana sayfayı düzenleyecekler burada çalışacak
func MainPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	db, errDb := sql.Open("sqlite3", "./forum.db")
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT ID, Title, UserName, LikeCount FROM POSTS ORDER BY PostDate desc")
	if err != nil {
		http.ServeFile(w, r, "static/index/index.html")
		return
	}
	defer rows.Close()

	var posts []Post

	for rows.Next() {
		var post Post
		err := rows.Scan(&post.ID, &post.Title, &post.UserName, &post.LikeCount)
		if err != nil {
			http.Error(w, "ERROR: Database scan error", http.StatusBadRequest)
			return
		}
		posts = append(posts, post)
	}

	err = rows.Err()
	if err != nil {
		http.Error(w, "ERROR: Row iteration error", http.StatusBadRequest)
		return
	}
	var tmpl *template.Template
	authenticated, _, _ := IsAuthenticated(r)
	if !authenticated {
		tmpl, err = template.ParseFiles("static/index/indexSessionless.html")
		if err != nil {
			http.Error(w, "ERROR: Unable to parse template", http.StatusInternalServerError)
			return
		}
	} else {
		tmpl, err = template.ParseFiles("static/index/index.html")
		if err != nil {
			http.Error(w, "ERROR: Unable to parse template", http.StatusInternalServerError)
			return
		}
	}

	err = tmpl.Execute(w, posts)
	if err != nil {
		http.Error(w, "ERROR: Unable to execute template", http.StatusInternalServerError)
	}
}

func PostPageHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "ERROR: Form values parsing", http.StatusBadRequest)
			return
		}

		id := r.FormValue("id")
		postID, atoiErr := strconv.Atoi(id)
		if atoiErr != nil {
			http.Error(w, "ERROR: Invalid ID format", http.StatusBadRequest)
			return
		}

		db, errDb := sql.Open("sqlite3", "./forum.db")
		if errDb != nil {
			http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
			return
		}
		defer db.Close()

		var post Post
		err := db.QueryRow("SELECT ID, Title, Content, UserName, LikeCount, PhotoPath FROM POSTS WHERE ID = ?", postID).Scan(&post.ID, &post.Title, &post.Content, &post.UserName, &post.LikeCount, &post.PhotoPath)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "ERROR: Post not found", http.StatusNotFound)
			} else {
				http.Error(w, "ERROR: Post cannot be retrieved", http.StatusInternalServerError)
			}
			return
		}

		commentRows, err := db.Query("SELECT ID, Comment, UserName, LikeCount FROM COMMENTS WHERE PostID = ? ORDER BY created_at desc", postID)
		if err != nil {
			http.Error(w, "ERROR: Query error for comments", http.StatusBadRequest)
			return
		}
		defer commentRows.Close()

		var comments []Comment

		for commentRows.Next() {
			var comment Comment
			err := commentRows.Scan(&comment.ID, &comment.Comment, &comment.UserName, &comment.LikeCount)
			if err != nil {
				http.Error(w, "ERROR: Database scan error", http.StatusBadRequest)
				return
			}
			replyRows, err := db.Query("SELECT ID, CommentID, UserID, Reply, CreatedAt FROM REPLIES WHERE CommentID = ?", comment.ID)
			if err != nil {
				http.Error(w, "ERROR: Database scan error", http.StatusBadRequest)
				return
			}
			defer replyRows.Close()

			var replies []Reply
			for replyRows.Next() {
				var reply Reply
				err := replyRows.Scan(&reply.ID, &reply.CommentID, &reply.UserID, &reply.Reply, &reply.CreatedAt)
				if err != nil {
					http.Error(w, "ERROR: Database scan error", http.StatusBadRequest)
					return
				}
				replies = append(replies, reply)
			}
			comment.Replies = replies
			comments = append(comments, comment)
		}

		err = commentRows.Err()
		if err != nil {
			http.Error(w, "ERROR: Comment Row iteration error", http.StatusBadRequest)
			return
		}

		data := PostWithComments{
			Post:     post,
			Comments: comments,
		}

		tmpl, err := template.ParseFiles("static/index/postpage.html")
		if err != nil {
			http.Error(w, "ERROR: Unable to parse template", http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "ERROR: Unable to execute template", http.StatusInternalServerError)
		}
	case "POST":
		authenticated, userID, userName := IsAuthenticated(r)
		if !authenticated {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "ERROR: Form values parsing", http.StatusBadRequest)
			return
		}

		id := r.FormValue("id")
		comment := r.FormValue("comment")

		if comment == "" {
			http.Error(w, "ERROR: You cannot create empty comment", http.StatusBadRequest)
			return
		}

		postID, atoiErr := strconv.Atoi(id)
		if atoiErr != nil {
			http.Error(w, "ERROR: Invalid ID format", http.StatusBadRequest)
			return
		}

		db, errDb := sql.Open("sqlite3", "./forum.db")
		if errDb != nil {
			http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
			return
		}
		defer db.Close()

		_, errEx := db.Exec(`INSERT INTO COMMENTS (PostID, UserId, UserName, Comment) VALUES (?, ?, ?, ?)`, postID, userID, userName, comment)
		if errEx != nil {
			http.Error(w, "ERROR: Post did not add to the database", http.StatusBadRequest)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/post?id=%d", postID), http.StatusSeeOther)
	}
}

func AddReplyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	authenticated, userID, _ := IsAuthenticated(r)
	if !authenticated {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "ERROR: Form values parsing", http.StatusBadRequest)
		return
	}

	commentID := r.FormValue("comment_id")
	reply := r.FormValue("reply")
	postID := r.FormValue("post_id")

	if commentID == "" || reply == "" || postID == "" {
		http.Error(w, "ERROR: Missing form values", http.StatusBadRequest)
		return
	}

	commentIDInt, atoiErr := strconv.Atoi(commentID)
	if atoiErr != nil {
		http.Error(w, "ERROR: Invalid comment ID format", http.StatusBadRequest)
		return
	}

	postIDInt, atoiErr := strconv.Atoi(postID)
	if atoiErr != nil {
		http.Error(w, "ERROR: Invalid post ID format", http.StatusBadRequest)
		return
	}

	db, errDb := sql.Open("sqlite3", "./forum.db")
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()

	_, err := db.Exec(`INSERT INTO REPLIES (CommentID, UserID, Reply, PostID) VALUES (?, ?, ?, ?)`, commentIDInt, userID, reply, postIDInt)
	if err != nil {
		http.Error(w, "ERROR: Reply did not add to the database", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/post?id=%s", postID), http.StatusSeeOther)
}

func DeletePost(w http.ResponseWriter, r *http.Request) {
	authenticated, userID, userName := IsAuthenticated(r)
	if !authenticated {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "ERROR: Form values parsing", http.StatusBadRequest)
		return
	}

	id := r.FormValue("id")
	postID, atoiErr := strconv.Atoi(id)
	if atoiErr != nil {
		http.Error(w, "ERROR: Invalid ID format", http.StatusBadRequest)
		return
	}

	db, errDb := sql.Open("sqlite3", "./forum.db")
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()

	var postUserID int
	var postUserName string

	err := db.QueryRow("SELECT UserID, UserName FROM POSTS WHERE ID = ?", postID).Scan(&postUserID, &postUserName)
	if err != nil {
		http.Error(w, "ERROR: Cannot find post from database", http.StatusBadRequest)
		return
	}

	if userID == postUserID && userName == postUserName {
		_, errDel := db.Exec(`DELETE FROM POSTS WHERE ID = ?`, postID)
		if errDel != nil {
			http.Error(w, "ERROR: Unable to delete post", http.StatusInternalServerError)
			return
		}
		_, errComDel := db.Exec(`DELETE FROM COMMENTS WHERE PostId = ?`, postID)
		if errComDel != nil {
			http.Error(w, "ERROR: Unable to delete post comments", http.StatusInternalServerError)
			return
		}
		_, errRepDel := db.Exec(`DELETE FROM REPLIES WHERE PostID = ?`, postID)
		if errRepDel != nil {
			http.Error(w, "ERROR: Unable to delete comment replies", http.StatusInternalServerError)
			return
		}
		_, errUserLikeDel := db.Exec(`DELETE FROM USERLIKES WHERE DeleteID = ?`, postID)
		if errUserLikeDel != nil {
			http.Error(w, "ERROR: Unable to delete user likes", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/myposts", http.StatusSeeOther)
}

func init() {
	var err error
	db, err = sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Fatal(err)
	}

	// Tabloları oluşturma
	createTables := `
    CREATE TABLE IF NOT EXISTS USERS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Email TEXT NOT NULL UNIQUE,
        UserName TEXT NOT NULL,
        Password TEXT NOT NULL,
		Role TEXT,
		session_token TEXT
    );
    CREATE TABLE IF NOT EXISTS POSTS (
		"ID" INTEGER UNIQUE,
		"UserID" INTEGER,
		"UserName" TEXT,
		"Title" TEXT,
		"Content" TEXT,
		"LikeCount" INTEGER DEFAULT 0,
		"CommentCount" INTEGER DEFAULT 0,
		"PostDate" TEXT NOT NULL DEFAULT (datetime('now')),
		"PhotoPath" TEXT,
		PRIMARY KEY("ID" AUTOINCREMENT)
    );
    CREATE TABLE IF NOT EXISTS COMMENTS (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        PostId INTEGER,
        UserId INTEGER,
		UserName TEXT,
        Comment TEXT NOT NULL,
		"LikeCount" INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(PostId) REFERENCES posts(ID),
        FOREIGN KEY(UserId) REFERENCES users(ID)
    );
	CREATE TABLE IF NOT EXISTS REPLIES (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        CommentID INTEGER,
		PostID INTEGER,
        UserID INTEGER,
        Reply TEXT,
		CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(CommentID) REFERENCES comments(ID),
		FOREIGN KEY(PostId) REFERENCES posts(ID),
		FOREIGN KEY(UserID) REFERENCES users(ID)
    );
		CREATE TABLE IF NOT EXISTS USERLIKES (
		ID INTEGER PRIMARY KEY AUTOINCREMENT,
		UserID INTEGER,
		PostID INTEGER,
		IsComment BOOLEAN,
		DeleteID INTEGER,
		Liked BOOLEAN,
		Disliked BOOLEAN,
		UNIQUE(UserID, PostID, IsComment)
	);`

	_, err = db.Exec(createTables)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Tablolar başarıyla oluşturuldu.")
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl, err := template.ParseFiles("static/register/register.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
	} else if r.Method == "POST" {
		email := r.FormValue("email")
		username := r.FormValue("username")
		password := r.FormValue("password")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		var userID int
		errMail := db.QueryRow("SELECT ID FROM USERS WHERE Email = ?", email).Scan(&userID)
		if errMail == nil {
			http.Error(w, "Email already taken", http.StatusBadRequest)
			return
		}

		errUsername := db.QueryRow("SELECT ID FROM USERS WHERE UserName = ?", username).Scan(&userID)
		if errUsername == nil {
			http.Error(w, "Username already taken", http.StatusBadRequest)
			return
		}

		_, err = db.Exec("INSERT INTO USERS (Email, UserName, Password, Role) VALUES (?, ?, ?, ?)", email, username, string(hashedPassword), "User")
		if err != nil {
			http.Error(w, "ERROR: Bad Request", http.StatusBadRequest)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var errorMsg string
	if r.Method == "POST" {
		email := r.FormValue("email")
		password := r.FormValue("password")

		var storedPassword string
		var userID int
		err := db.QueryRow("SELECT ID, Password FROM USERS WHERE Email = ?", email).Scan(&userID, &storedPassword)
		if err != nil {
			errorMsg = "Invalid email or password"
		} else {
			err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
			if err != nil {
				errorMsg = "Invalid email or password"
			} else {
				sessionToken, err := uuid.NewV4()
				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}

				http.SetCookie(w, &http.Cookie{
					Name:     "session_token",
					Value:    sessionToken.String(),
					Expires:  time.Now().Add(24 * time.Hour),
					HttpOnly: true,
				})

				_, err = db.Exec("UPDATE USERS SET session_token = ? WHERE ID = ?", sessionToken.String(), userID)
				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
		}
	}

	tmpl, err := template.ParseFiles("static/login/login.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, errorMsg)
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := "https://accounts.google.com/o/oauth2/auth?client_id=" + googleClientID +
		"&redirect_uri=http://localhost:8080/callback/google" +
		"&scope=https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email" +
		"&response_type=code" +
		"&state=random-string"
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state != "random-string" {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code in response", http.StatusBadRequest)
		return
	}

	token, err := exchangeGoogleCodeForToken(code)
	if err != nil {
		http.Error(w, "Failed to exchange code for token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	userInfo, err := getGoogleUserInfo(token)
	if err != nil {
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	email, emailOk := userInfo["email"].(string)
	name, nameOk := userInfo["name"].(string)

	if !emailOk || !nameOk || email == "" {
		log.Printf("Google user info is missing required fields: %+v", userInfo)
		http.Error(w, "Failed to get valid user info", http.StatusInternalServerError)
		return
	}

	// Kullanıcıyı veritabanında kontrol et
	var userID int
	err = db.QueryRow("SELECT ID FROM USERS WHERE Email = ?", email).Scan(&userID)
	if err == sql.ErrNoRows {
		// Kullanıcı mevcut değilse, yeni kullanıcı oluştur
		_, err = db.Exec("INSERT INTO USERS (Email, UserName, Password) VALUES (?, ?, ?)", email, name, "")
		if err != nil {
			http.Error(w, "Failed to save user: "+err.Error(), http.StatusInternalServerError)
			return
		}
		err = db.QueryRow("SELECT ID FROM USERS WHERE Email = ?", email).Scan(&userID)
	} else if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Kullanıcıyı giriş yapmış olarak işaretleyin
	sessionToken, err := uuid.NewV4()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken.String(),
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Path:     "/",
	})

	_, err = db.Exec("UPDATE USERS SET session_token = ? WHERE ID = ?", sessionToken.String(), userID)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	url := "https://github.com/login/oauth/authorize?client_id=" + githubClientID +
		"&redirect_uri=http://localhost:8080/callback/github" +
		"&scope=read:user user:email" +
		"&state=random-string"
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state != "random-string" {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code in response", http.StatusBadRequest)
		return
	}

	token, err := exchangeGitHubCodeForToken(code)
	if err != nil {
		log.Printf("Failed to exchange code for token: %v", err)
		http.Error(w, "Failed to exchange code for token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	userInfo, err := getGitHubUserInfo(token)
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	email, emailOk := userInfo["email"].(string)
	if !emailOk || email == "" {
		// Email doğrudan alınamadıysa, ek endpoint'ten email bilgilerini al
		emails, err := getGitHubUserEmails(token)
		if err != nil || len(emails) == 0 {
			log.Printf("Failed to get valid user info: %v", err)
			http.Error(w, "Failed to get valid user info", http.StatusInternalServerError)
			return
		}
		email = emails[0]
	}

	username, usernameOk := userInfo["login"].(string)
	if !usernameOk || username == "" {
		http.Error(w, "Failed to get valid user info", http.StatusInternalServerError)
		return
	}

	// Kullanıcıyı veritabanında kontrol et
	var userID int
	err = db.QueryRow("SELECT ID FROM USERS WHERE Email = ?", email).Scan(&userID)
	if err == sql.ErrNoRows {
		// Kullanıcı mevcut değilse, yeni kullanıcı oluştur
		_, err = db.Exec("INSERT INTO USERS (Email, UserName, Password) VALUES (?, ?, ?)", email, username, "")
		if err != nil {
			log.Printf("Failed to save user: %v", err)
			http.Error(w, "Failed to save user: "+err.Error(), http.StatusInternalServerError)
			return
		}
		err = db.QueryRow("SELECT ID FROM USERS WHERE Email = ?", email).Scan(&userID)
	} else if err != nil {
		log.Printf("Database error: %v", err)
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Kullanıcıyı giriş yapmış olarak işaretleyin
	sessionToken, err := uuid.NewV4()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken.String(),
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	_, err = db.Exec("UPDATE USERS SET session_token = ? WHERE ID = ?", sessionToken.String(), userID)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func exchangeGoogleCodeForToken(code string) (string, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", googleClientID)
	data.Set("client_secret", googleClientSecret)
	data.Set("redirect_uri", "http://localhost:8080/callback/google")
	data.Set("grant_type", "authorization_code")

	resp, err := http.PostForm("https://oauth2.googleapis.com/token", data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if token, ok := result["access_token"].(string); ok {
		return token, nil
	}
	return "", fmt.Errorf("no access token in response")
}

func getGoogleUserInfo(token string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&userInfo)
	return userInfo, nil
}

func exchangeGitHubCodeForToken(code string) (string, error) {
	data := url.Values{}
	data.Set("client_id", githubClientID)
	data.Set("client_secret", githubClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", "http://localhost:8080/callback/github")

	req, err := http.NewRequest("POST", "https://github.com/login/oauth/access_token", nil)
	if err != nil {
		return "", err
	}
	req.URL.RawQuery = data.Encode()
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if token, ok := result["access_token"].(string); ok {
		return token, nil
	}
	return "", fmt.Errorf("no access token in response")
}

func getGitHubUserInfo(token string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&userInfo)
	return userInfo, nil
}

func getGitHubUserEmails(token string) ([]string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var emails []struct {
		Email      string `json:"email"`
		Primary    bool   `json:"primary"`
		Verified   bool   `json:"verified"`
		Visibility string `json:"visibility"`
	}
	err = json.NewDecoder(resp.Body).Decode(&emails)
	if err != nil {
		return nil, err
	}

	var result []string
	for _, e := range emails {
		if e.Verified {
			result = append(result, e.Email)
		}
	}
	return result, nil
}

func CreatePost(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		http.ServeFile(w, r, "static/index/createpost.html")
	case "POST":
		authenticated, userId, userName := IsAuthenticated(r)
		if !authenticated {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		r.ParseMultipartForm(10 << 20)

		if err := r.ParseForm(); err != nil {
			http.Error(w, "ERROR: Form values parsing", http.StatusBadRequest)
			return
		}
		title := r.FormValue("title")
		content := r.FormValue("content")
		if title == "" || content == "" {
			http.Error(w, "ERROR: Content or title cannot empty", http.StatusBadRequest)
			return
		}

		var PhotoPath string
		file, handler, err := r.FormFile("photo")
		if err == nil {
			defer file.Close()

			// Fotoğrafı uploads dizinine kaydet
			tempFile, err := os.Create(fmt.Sprintf("./uploads/%s", handler.Filename))
			if err != nil {
				http.Error(w, "Unable to save file", http.StatusInternalServerError)
				return
			}
			defer tempFile.Close()
			io.Copy(tempFile, file)
			PhotoPath = fmt.Sprintf("/uploads/%s", handler.Filename)
		}

		db, errDb := sql.Open("sqlite3", "./forum.db")
		if errDb != nil {
			http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
			return
		}
		defer db.Close()

		result, errEx := db.Exec(`INSERT INTO POSTS (Title, UserID, UserName, Content, PhotoPath) VALUES (?, ?, ?, ?, ?)`, title, userId, userName, content, PhotoPath)
		if errEx != nil {
			http.Error(w, "ERROR: Post did not added into the database", http.StatusBadRequest)
			return
		}
		postID, err := result.LastInsertId()
		if err != nil {
			http.Error(w, "ERROR: Could not retrieve post ID", http.StatusBadRequest)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/post?id=%d", postID), http.StatusSeeOther)
	}
}

func IsAuthenticated(r *http.Request) (bool, int, string) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return false, 0, ""
	}

	var userID int
	var userName string

	err = db.QueryRow("SELECT ID, UserName FROM USERS WHERE session_token = ?", cookie.Value).Scan(&userID, &userName)
	if err != nil {
		return false, 0, ""
	}

	return true, userID, userName
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	_, err = db.Exec("UPDATE USERS SET session_token = '' WHERE session_token = ?", cookie.Value)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	expiredCookie := &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	}

	http.SetCookie(w, expiredCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func DeleteComment(w http.ResponseWriter, r *http.Request) {
	authenticated, userId, userName := IsAuthenticated(r)
	if !authenticated {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	commentId := r.FormValue("id")
	comId, errStr := strconv.Atoi(commentId)
	if errStr != nil {
		http.Error(w, "ERROR: Invalid comment ID", http.StatusBadRequest)
		return
	}

	var comUserId int
	var comUserName string
	var comPostId int

	err := db.QueryRow("SELECT UserId, UserName, PostId FROM COMMENTS WHERE ID = ?", comId).Scan(&comUserId, &comUserName, &comPostId)
	if err != nil {
		http.Error(w, "ERROR: Comment cannot found in the database", http.StatusBadRequest)
		return
	}

	if userId == comUserId && userName == comUserName {
		_, errComDel := db.Exec(`DELETE FROM COMMENTS WHERE ID = ?`, comId)
		if errComDel != nil {
			http.Error(w, "ERROR: Unable to delete comment", http.StatusInternalServerError)
			return
		}
		_, errRepDel := db.Exec(`DELETE FROM REPLIES WHERE CommentID = ?`, comId)
		if errRepDel != nil {
			http.Error(w, "ERROR: Unable to delete comment replies", http.StatusInternalServerError)
			return
		}
		_, errUserLikeDel := db.Exec(`DELETE FROM USERLIKES WHERE PostID = ?`, comId)
		if errUserLikeDel != nil {
			http.Error(w, "ERROR: Unable to delete user likes", http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/mycomments", http.StatusSeeOther)
}

func LikePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	authenticated, userID, _ := IsAuthenticated(r)
	if !authenticated {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	id := r.FormValue("id")
	isComment := r.FormValue("isComment") == "true"
	postID := r.FormValue("post_id")
	idInt, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	postIdInt, err := strconv.Atoi(postID)
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	db, errDb := sql.Open("sqlite3", "./forum.db")
	if errDb != nil {
		http.Error(w, "Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()

	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM UserLikes WHERE UserID = ? AND PostID = ? AND IsComment = ?)", userID, idInt, isComment).Scan(&exists)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if !exists {
		_, err = db.Exec(`INSERT INTO UserLikes (UserID, PostID, IsComment, DeleteID, Liked, Disliked) VALUES (?, ?, ?, ?, 0, 0)`, userID, idInt, isComment, postIdInt)
		if err != nil {
			http.Error(w, "Failed to create user like record", http.StatusInternalServerError)
			return
		}
	}

	var likeExists bool
	var dislikeExists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM UserLikes WHERE UserID = ? AND PostID = ? AND IsComment = ? AND Liked = 1)", userID, idInt, isComment).Scan(&likeExists)
	if err != nil {
		http.Error(w, "ERROR: Invalid query", http.StatusBadRequest)
		return
	}
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM UserLikes WHERE UserID = ? AND PostID = ? AND IsComment = ? AND Disliked = 1)", userID, idInt, isComment).Scan(&dislikeExists)
	if err != nil {
		http.Error(w, "ERROR: Invalid query", http.StatusBadRequest)
		return
	}

	if likeExists {
		if isComment {
			_, err = db.Exec(`UPDATE COMMENTS SET LikeCount = LikeCount - 1 WHERE ID = ?`, idInt)
		} else {
			_, err = db.Exec(`UPDATE POSTS SET LikeCount = LikeCount - 1 WHERE ID = ?`, idInt)
		}

		if err == nil {
			_, err = db.Exec(`UPDATE UserLikes SET Liked = 0 WHERE UserID = ? AND PostID = ? AND IsComment = ?`, userID, idInt, isComment)
		}
	} else if dislikeExists {
		if isComment {
			_, err = db.Exec(`UPDATE COMMENTS SET LikeCount = LikeCount + 2 WHERE ID = ?`, idInt)
		} else {
			_, err = db.Exec(`UPDATE POSTS SET LikeCount = LikeCount + 2 WHERE ID = ?`, idInt)
		}

		if err == nil {
			_, err = db.Exec(`UPDATE UserLikes SET Liked = 1 WHERE UserID = ? AND PostID = ? AND IsComment = ?`, userID, idInt, isComment)
			_, err = db.Exec(`UPDATE UserLikes SET Disliked = 0 WHERE UserID = ? AND PostID = ? AND IsComment = ?`, userID, idInt, isComment)
		}
	} else {
		if isComment {
			_, err = db.Exec(`UPDATE COMMENTS SET LikeCount = LikeCount + 1 WHERE ID = ?`, idInt)
		} else {
			_, err = db.Exec(`UPDATE POSTS SET LikeCount = LikeCount + 1 WHERE ID = ?`, idInt)
		}

		if err == nil {
			_, err = db.Exec(`UPDATE UserLikes SET Liked = 1 WHERE UserID = ? AND PostID = ? AND IsComment = ?`, userID, idInt, isComment)
		}
	}

	http.Redirect(w, r, fmt.Sprintf("/post?id=%s", postID), http.StatusSeeOther)
}

func DislikePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	authenticated, userID, _ := IsAuthenticated(r)
	if !authenticated {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	id := r.FormValue("id")
	isComment := r.FormValue("isComment") == "true"
	postID := r.FormValue("post_id")
	idInt, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	db, errDb := sql.Open("sqlite3", "./forum.db")
	if errDb != nil {
		http.Error(w, "Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()

	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM UserLikes WHERE UserID = ? AND PostID = ? AND IsComment = ?)", userID, idInt, isComment).Scan(&exists)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if !exists {
		_, err = db.Exec(`INSERT INTO UserLikes (UserID, PostID, IsComment, Liked, Disliked) VALUES (?, ?, ?, 0, 0)`, userID, idInt, isComment)
		if err != nil {
			http.Error(w, "Failed to create user like record", http.StatusInternalServerError)
			return
		}
	}

	var dislikeExists bool
	var likeExists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM UserLikes WHERE UserID = ? AND PostID = ? AND IsComment = ? AND Disliked = 1)", userID, idInt, isComment).Scan(&dislikeExists)
	if err != nil {
		http.Error(w, "ERROR: Invalid query", http.StatusBadRequest)
		return
	}
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM UserLikes WHERE UserID = ? AND PostID = ? AND IsComment = ? AND Liked = 1)", userID, idInt, isComment).Scan(&likeExists)
	if err != nil {
		http.Error(w, "ERROR: Invalid query", http.StatusBadRequest)
		return
	}

	if likeExists {
		if isComment {
			_, err = db.Exec(`UPDATE COMMENTS SET LikeCount = LikeCount - 2 WHERE ID = ?`, idInt)
		} else {
			_, err = db.Exec(`UPDATE POSTS SET LikeCount = LikeCount - 2 WHERE ID = ?`, idInt)
		}

		if err == nil {
			_, err = db.Exec(`UPDATE UserLikes SET Disliked = 1 WHERE UserID = ? AND PostID = ? AND IsComment = ?`, userID, idInt, isComment)
			_, err = db.Exec(`UPDATE UserLikes SET Liked = 0 WHERE UserID = ? AND PostID = ? AND IsComment = ?`, userID, idInt, isComment)
		}
	} else if dislikeExists {
		if isComment {
			_, err = db.Exec(`UPDATE COMMENTS SET LikeCount = LikeCount + 1 WHERE ID = ?`, idInt)
		} else {
			_, err = db.Exec(`UPDATE POSTS SET LikeCount = LikeCount + 1 WHERE ID = ?`, idInt)
		}

		if err == nil {
			_, err = db.Exec(`UPDATE UserLikes SET Disliked = 0 WHERE UserID = ? AND PostID = ? AND IsComment = ?`, userID, idInt, isComment)
		}

	} else {

		if isComment {
			_, err = db.Exec(`UPDATE COMMENTS SET LikeCount = LikeCount - 1 WHERE ID = ?`, idInt)
		} else {
			_, err = db.Exec(`UPDATE POSTS SET LikeCount = LikeCount - 1 WHERE ID = ?`, idInt)
		}

		if err == nil {
			_, err = db.Exec(`UPDATE UserLikes SET Disliked = 1 WHERE UserID = ? AND PostID = ? AND IsComment = ?`, userID, idInt, isComment)
		}
	}
	http.Redirect(w, r, fmt.Sprintf("/post?id=%s", postID), http.StatusSeeOther)
}

func MyPostsHandler(w http.ResponseWriter, r *http.Request) {
	authenticated, userID, _ := IsAuthenticated(r)
	if !authenticated {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	db, errDb := sql.Open("sqlite3", "./forum.db")
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT ID, Title, UserName, LikeCount FROM POSTS WHERE UserID = ? ORDER BY PostDate desc", userID)
	if err != nil {
		http.Error(w, "ERROR: Query error", http.StatusBadRequest)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		err := rows.Scan(&post.ID, &post.Title, &post.UserName, &post.LikeCount)
		if err != nil {
			http.Error(w, "ERROR: Database scan error", http.StatusBadRequest)
			return
		}
		posts = append(posts, post)
	}

	tmpl, err := template.ParseFiles("static/index/myposts.html")
	if err != nil {
		http.Error(w, "ERROR: Unable to parse template", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, posts)
	if err != nil {
		http.Error(w, "ERROR: Unable to execute template", http.StatusInternalServerError)
	}
}

func MyCommentsHandler(w http.ResponseWriter, r *http.Request) {
	authenticated, userID, _ := IsAuthenticated(r)
	if !authenticated {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	db, errDb := sql.Open("sqlite3", "./forum.db")
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		log.Printf("ERROR: Database cannot open - %v", errDb)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT ID, Comment, UserName, LikeCount FROM COMMENTS WHERE UserId = ? ORDER BY created_at desc", userID)
	if err != nil {
		http.Error(w, "ERROR: Query error", http.StatusBadRequest)
		log.Printf("ERROR: Query error - %v", err)
		return
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var comment Comment
		err := rows.Scan(&comment.ID, &comment.Comment, &comment.UserName, &comment.LikeCount)
		if err != nil {
			http.Error(w, "ERROR: Database scan error", http.StatusBadRequest)
			log.Printf("ERROR: Database scan error - %v", err)
			return
		}
		comments = append(comments, comment)
	}

	err = rows.Err()
	if err != nil {
		http.Error(w, "ERROR: Row iteration error", http.StatusBadRequest)
		log.Printf("ERROR: Row iteration error - %v", err)
		return
	}

	tmpl, err := template.ParseFiles("static/index/mycomments.html")
	if err != nil {
		http.Error(w, "ERROR: Unable to parse template", http.StatusInternalServerError)
		log.Printf("ERROR: Unable to parse template - %v", err)
		return
	}

	err = tmpl.Execute(w, comments)
	if err != nil {
		http.Error(w, "ERROR: Unable to execute template", http.StatusInternalServerError)
		log.Printf("ERROR: Unable to execute template - %v", err)
	}
}

func LikedPostsHandler(w http.ResponseWriter, r *http.Request) {
	authenticated, userID, _ := IsAuthenticated(r)
	if !authenticated {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	db, errDb := sql.Open("sqlite3", "./forum.db")
	if errDb != nil {
		http.Error(w, "ERROR: Database cannot open", http.StatusBadRequest)
		return
	}
	defer db.Close()

	rows, err := db.Query(`
        SELECT POSTS.ID, POSTS.Title, POSTS.UserName, POSTS.LikeCount
        FROM POSTS
        INNER JOIN USERLIKES ON POSTS.ID = USERLIKES.PostID
        WHERE USERLIKES.UserID = ? AND USERLIKES.Liked = 1 AND USERLIKES.IsComment = 0
        ORDER BY POSTS.PostDate DESC
    `, userID)
	if err != nil {
		http.Error(w, "ERROR: Query error", http.StatusBadRequest)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		err := rows.Scan(&post.ID, &post.Title, &post.UserName, &post.LikeCount)
		if err != nil {
			http.Error(w, "ERROR: Database scan error", http.StatusBadRequest)
			return
		}
		posts = append(posts, post)
	}

	tmpl, err := template.ParseFiles("static/index/likedposts.html")
	if err != nil {
		http.Error(w, "ERROR: Unable to parse template", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, posts)
	if err != nil {
		http.Error(w, "ERROR: Unable to execute template", http.StatusInternalServerError)
	}
}

func DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	authenticated, userID, _ := IsAuthenticated(r)
	if !authenticated {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Kullanıcının yaptığı tüm yorumları ve beğenileri sil
	_, err = db.Exec("DELETE FROM USERLIKES WHERE UserID = ?", userID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("DELETE FROM REPLIES WHERE UserID = ?", userID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("DELETE FROM COMMENTS WHERE UserID = ?", userID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Kullanıcının oluşturduğu tüm gönderileri sil
	_, err = db.Exec("DELETE FROM POSTS WHERE UserID = ?", userID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Kullanıcıyı veritabanından sil
	_, err = db.Exec("DELETE FROM USERS WHERE ID = ?", userID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Oturumu sonlandır
	_, err = db.Exec("UPDATE USERS SET session_token = '' WHERE ID = ?", userID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Kullanıcının tarayıcıdaki oturum çerezini kaldır
	expiredCookie := &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	}
	http.SetCookie(w, expiredCookie)

	// Kullanıcıyı yönlendir
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
