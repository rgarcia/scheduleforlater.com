package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
)

func main() {
	var port string
	if port = os.Getenv("PORT"); port == "" {
		log.Fatal("must set PORT")
	}

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello", html.EscapeString(r.URL.Path))
	})

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
