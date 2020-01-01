package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
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
	Message string `json:"message"`
}

var db *sql.DB

func main() {
	router := mux.NewRouter()

	pgUrl, err := pq.ParseURL("postgres://amuodazc:jsXKFS4Fe4gNvlmOQcYVG6SAHFejmp99@balarama.db.elephantsql.com:5432/amuodazc")
	if err != nil {
		log.Fatal(err)
	}

	db, err = sql.Open("postgres", pgUrl)
	if err != nil {
		log.Fatal(err)
	}

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleware(ProtectedEndpoint)).Methods("GET")

	log.Println("Listening on port 8000...")
	err = http.ListenAndServe(":8000", router)
	// application will exit if some error emerged from server start up
	log.Fatal(err)
}

func respondWithError(res http.ResponseWriter, status int, error Error) {
	res.WriteHeader(status)
	json.NewEncoder(res).Encode(error)
}

func respondWithJSON(res http.ResponseWriter, data interface{}) {
	json.NewEncoder(res).Encode(data)
}

func signup(res http.ResponseWriter, req *http.Request) {
	var user User
	var error Error
	json.NewDecoder(req.Body).Decode(&user)
	spew.Dump(user)

	if user.Email == "" {
		error.Message = "Email is missing"
		respondWithError(res, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "Password is missing"
		respondWithError(res, http.StatusBadRequest, error)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		log.Fatal(err.Error())
	}

	user.Password = string(hash)

	insertStatement := "insert into users (email, password) values($1, $2) returning id;"
	err = db.QueryRow(insertStatement, user.Email, user.Password).Scan(&user.ID)
	if err != nil {
		error.Message = err.Error()
		respondWithError(res, http.StatusInternalServerError, error)
		return
	}

	// as we want to return user object in response, we want to hide password
	// todo ask why in Q&A
	user.Password = ""

	res.Header().Set("Content-Type", "application/json")
	respondWithJSON(res, user)
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
