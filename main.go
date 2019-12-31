package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
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
	var db *sql.DB

	pgUrl, err := pq.ParseURL("postgres://amuodazc:jsXKFS4Fe4gNvlmOQcYVG6SAHFejmp99@balarama.db.elephantsql.com:5432/amuodazc")
	if err != nil {
		log.Fatal(err)
	}

	db, err = sql.Open("postgres", pgUrl)
	if err != nil {
		log.Fatal(err)
	}
	db.Close()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleware(ProtectedEndpoint)).Methods("GET")

	log.Println("Listening on port 8000...")
	err = http.ListenAndServe(":8000", router)
	// application will exit if some error emerged from server start up
	log.Fatal(err)
}

func signup(res http.ResponseWriter, req *http.Request) {
	var user User
	var error Error
	json.NewDecoder(req.Body).Decode(&user)
	spew.Dump(user)

	if user.Email == "" && user.Password == "" {
		error.Message = "Email or password are missing"
	}
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
