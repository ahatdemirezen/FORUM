package server

import (
	"fmt"
	"net/http"
)

const port = ":8080"

func StartServer() {
	fmt.Printf("Server is running on %s", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		panic(err)
	}
}
