package structs

type Post struct {
	ID        int    `json:"id"`
	UserID    int    `json:"userid"`
	UserName  string `json:"username"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	LikeCount int    `json:"likecount"`
	PhotoPath string `json:"photopath"`
	PostDate  string `json:"postdate"`
}

type Comment struct {
	ID        int    `json:"id"`
	PostId    int    `json:"postid"`
	UserId    int    `json:"userid"`
	UserName  string `json:"username"`
	Comment   string `json:"comment"`
	LikeCount int    `json:"likecount"`
}

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	UserName string `json:"username"`
	Role     string `json:"role"`
}

type PostWithComments struct {
	Post     Post
	Comments []Comment
}

type PageData struct {
	Posts []Post `json:"posts"`
}

type AdminNotifications struct {
	UserName    string `json:"username"`
	Email       string `json:"email"`
	Explanation string `json:"explanation"`
}
