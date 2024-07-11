package main

import (
	"forum/backend/database"
	"forum/backend/handlers"
	"forum/backend/readenv"
	"forum/backend/server"
)

func main() {
	readenv.LoadEnv()
	database.CreateDatabaseIfNotExists()

	handlers.ImportHandlers()

	server.StartServer()
}
