package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"github.com/subosito/gotenv"
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

func init() {
	gotenv.Load()
}

func main() {
	router := mux.NewRouter()

	pgURL, err := pq.ParseURL(os.Getenv("ELEPHANTSQL_URL"))
	if err != nil {
		log.Fatal(err)
	}

	db, err = sql.Open("postgres", pgURL)
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

func GenerateToken(user User) (string, error) {
	var err error
	secret := os.Getenv("SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})

	tokenSigned, err := token.SignedString([]byte(secret))

	if err != nil {
		log.Fatal(err)
	}

	return tokenSigned, nil
}

func login(res http.ResponseWriter, req *http.Request) {
	var user User
	var jwt JWT
	var error Error

	json.NewDecoder(req.Body).Decode(&user)

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

	password := user.Password

	row := db.QueryRow("select * from users where email=$1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "User does not exist"
			respondWithError(res, http.StatusBadRequest, error)
			return
		} else {
			log.Fatal(err)
		}
	}

	hashedPassword := user.Password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		error.Message = "Password is not valid"
		respondWithError(res, http.StatusBadRequest, error)
		return
	}

	token, err := GenerateToken(user)
	if err != nil {
		log.Fatal(err)
	}

	res.WriteHeader(http.StatusOK)
	jwt.Token = token
	respondWithJSON(res, jwt)

}

// ProtectedEndpoint ...
func ProtectedEndpoint(res http.ResponseWriter, req *http.Request) {
	res.Write([]byte("/protected endpoint hit"))
}

// TokenVerifyMiddleware ...
func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	secret := os.Getenv("SECRET")
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		var errorObject Error
		authHeader := req.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}

				return []byte(secret), nil
			})

			if err != nil {
				errorObject.Message = err.Error()
				respondWithError(res, http.StatusBadRequest, errorObject)
				return
			}

			if token.Valid {
				next.ServeHTTP(res, req)
			} else {
				errorObject.Message = err.Error()
				respondWithError(res, http.StatusUnauthorized, errorObject)
				return
			}

		} else {
			errorObject.Message = "Invalid token"
			respondWithError(res, http.StatusUnauthorized, errorObject)
			return
		}
	})
}
