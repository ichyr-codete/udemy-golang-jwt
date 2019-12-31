package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"error"`
}

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleware(ProtectedEndpoint)).Methods("GET")

	log.Println("Listening on port 8000...")
	err := http.ListenAndServe(":8000", router)
	// application will exit if some error emerged from server start up
	log.Fatal(err)
}

func signup(res http.ResponseWriter, req *http.Request) {
	log.Println("/signup called")
}

func login(res http.ResponseWriter, req *http.Request) {
	log.Println("/login  called")
}

// ProtectedEndpoint ...
func ProtectedEndpoint(res http.ResponseWriter, req *http.Request) {
	log.Println("/protected  called")
}

// TokenVerifyMiddleware ...
func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	log.Println("token verify middleware called")
	return next
}
