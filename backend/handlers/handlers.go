package handlers

import (
	"net/http"

	"forum/backend/controllers/admincontrols/admincommentsdelete"
	"forum/backend/controllers/admincontrols/adminnotifications"
	"forum/backend/controllers/admincontrols/messagetoadmin"
	"forum/backend/controllers/login"
	"forum/backend/controllers/logout"
	"forum/backend/controllers/register"
	"forum/backend/facebooklogin"
	"forum/backend/githublogin"
	"forum/backend/googlelogin"
	"forum/frontend/pages/admincontrol/admincomments"
	"forum/frontend/pages/admincontrol/adminmoderators"
	"forum/frontend/pages/admincontrol/adminusers"
	"forum/frontend/pages/admincontrol/notificationsforadminpage"

	admincommentscontrol "forum/backend/controllers/admincontrols/admincomments"

	adminmoderatorcontrol "forum/backend/controllers/admincontrols/adminmoderator"
	admindeletecontrol "forum/backend/controllers/admincontrols/adminpostdelete"
	adminpostcontrol "forum/backend/controllers/admincontrols/adminposts"
	admincontrolusers "forum/backend/controllers/admincontrols/adminusers"

	adminpost "forum/frontend/pages/admincontrol/adminpost"

	createcomment "forum/backend/controllers/create/createComment"
	createpost "forum/backend/controllers/create/createPost"
	deleteaccount "forum/backend/controllers/delete/deleteAccount"
	deletecomment "forum/backend/controllers/delete/deleteComment"
	deletepost "forum/backend/controllers/delete/deletePost"
	getallposts "forum/backend/controllers/get/getAllPosts"
	getmycomments "forum/backend/controllers/get/getMyComments"
	getmyposts "forum/backend/controllers/get/getMyPosts"
	getmyvotedposts "forum/backend/controllers/get/getMyVotedPosts"
	getpostandcomments "forum/backend/controllers/get/getPostAndComments"
	getsearchedposts "forum/backend/controllers/get/getSearchedPosts"

	downvote "forum/backend/controllers/votes/downVote"
	upvote "forum/backend/controllers/votes/upVote"

	admincontrol "forum/frontend/pages/admincontrol/mainadmin"
	createpostpage "forum/frontend/pages/createPostPage"
	deleteaccountpage "forum/frontend/pages/deleteAccountPage"
	loginpage "forum/frontend/pages/loginPage"
	mainpage "forum/frontend/pages/mainPage"
	postpage "forum/frontend/pages/postPage"
	mycommentspage "forum/frontend/pages/profile/myCommentsPage"
	mypostspage "forum/frontend/pages/profile/myPostsPage"
	myvotedpostspage "forum/frontend/pages/profile/myVotedPostsPage"
	registerpage "forum/frontend/pages/registerPage"
	searchedpostspage "forum/frontend/pages/searchedPostsPage"
)

func ImportHandlers() {
	// API
	http.HandleFunc("/api/register", register.Register)
	http.HandleFunc("/api/login", login.Login)
	http.HandleFunc("/api/logout", logout.Logout)
	http.HandleFunc("/api/createpost", createpost.CreatePost)
	http.HandleFunc("/api/createcomment", createcomment.CreateComment)
	http.HandleFunc("/api/deleteaccount", deleteaccount.DeleteAccount)
	http.HandleFunc("/api/deletepost", deletepost.DeletePost)
	http.HandleFunc("/api/deletecomment", deletecomment.DeleteComment)
	http.HandleFunc("/api/upvote", upvote.UpVote)
	http.HandleFunc("/api/downvote", downvote.DownVote)
	http.HandleFunc("/api/allposts", getallposts.GetAllPosts)
	http.HandleFunc("/api/postandcomments", getpostandcomments.GetPostAndComments)
	http.HandleFunc("/api/myposts", getmyposts.GetMyPosts)
	http.HandleFunc("/api/mycomments", getmycomments.GetMyComments)
	http.HandleFunc("/api/myvotedposts", getmyvotedposts.GetMyVotedPosts)
	http.HandleFunc("/api/searchedposts", getsearchedposts.GetSearchedPosts)
	http.HandleFunc("/api/adminusers", admincontrolusers.AdminUsersHandler)
	http.HandleFunc("/api/moderators", adminmoderatorcontrol.AdminModeratorsHandler)
	http.HandleFunc("/api/adminposts", adminpostcontrol.AdminPostsHandler)
	http.HandleFunc("/api/admincomments", admincommentscontrol.AdminCommentsHandler)
	http.HandleFunc("/api/admindeletepost", admindeletecontrol.DeletePostHandler)
	http.HandleFunc("/api/admindeletecomments", admincommentsdelete.DeleteCommentsHandler)
	http.HandleFunc("/api/mod-request", messagetoadmin.HandlerGetMessageForAdmin)
	http.HandleFunc("/api/adminnotifications", adminnotifications.AdminNotificiationsHandler)

	// Front-end
	http.HandleFunc("/", mainpage.MainPage)
	http.HandleFunc("/register", registerpage.RegisterPage)
	http.HandleFunc("/login", loginpage.LoginPage)
	http.HandleFunc("/github/login", githublogin.GithubLoginHandler)
	http.HandleFunc("/github/register", githublogin.GithubRegisterHandler)
	http.HandleFunc("/github/callback", githublogin.GithubCallbackHandler)
	http.HandleFunc("/google/login", googlelogin.GoogleLoginHandler)
	http.HandleFunc("/google/register", googlelogin.GoogleRegisterHandler)

	http.HandleFunc("/google/callback", googlelogin.GoogleCallbackHandler)

	http.HandleFunc("/facebook/login", facebooklogin.FacebookLoginHandler)
	http.HandleFunc("/facebook/register", facebooklogin.FacebookRegisterHandler)
	http.HandleFunc("/facebook/callback", facebooklogin.FacebookCallbackHandler)
	http.HandleFunc("/createpost", createpostpage.CreatePostPage)
	http.HandleFunc("/post", postpage.PostPage)
	http.HandleFunc("/createcomment", postpage.PostPageCreateComment)
	http.HandleFunc("/upvote", postpage.PostPageUpVote)
	http.HandleFunc("/downvote", postpage.PostPageDownVote)
	http.HandleFunc("/deleteaccount", deleteaccountpage.DeleteAccountPage)
	http.HandleFunc("/myposts", mypostspage.MyPostsPage)
	http.HandleFunc("/deletepost", mypostspage.DeleteMyPost)
	http.HandleFunc("/mycomments", mycommentspage.MyCommentsPage)
	http.HandleFunc("/deletecomment", mycommentspage.DeleteMyComment)
	http.HandleFunc("/myvotedposts", myvotedpostspage.MyVotedPostsPage)
	http.HandleFunc("/search", searchedpostspage.SearchedPostsPage)
	http.HandleFunc("/admin/moderators", adminmoderators.AdminModeratorPage)
	http.HandleFunc("/admin/users", adminusers.UsersPageForAdmin)
	http.HandleFunc("/admin/posts", adminpost.PostPageForAdmin)
	http.HandleFunc("/admin/comments", admincomments.CommentsPageForAdmin)
	http.HandleFunc("/admin/deletepost", adminpost.DeletePostPage)
	http.HandleFunc("/admin/deletecomment", admincomments.DeleteCommentsPage)
	http.HandleFunc("/admin/message", notificationsforadminpage.NotificationsPageForAdmin)

	http.HandleFunc("/admin", admincontrol.AdminHandler)

	http.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("./uploads"))))

	fs := http.FileServer(http.Dir("./frontend"))
	http.Handle("/frontend/", http.StripPrefix("/frontend/", fs))
}
