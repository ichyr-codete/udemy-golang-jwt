package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/ichyr-codete/udemy-golang-jwt/models"
	"github.com/ichyr-codete/udemy-golang-jwt/utils"
	"golang.org/x/crypto/bcrypt"
)

type Controller struct{}

// Signup ...
func (c *Controller) Signup(db *sql.DB) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var user models.User
		var error models.Error
		json.NewDecoder(req.Body).Decode(&user)

		if user.Email == "" {
			error.Message = "Email is missing"
			utils.RespondWithError(res, http.StatusBadRequest, error)
			return
		}

		if user.Password == "" {
			error.Message = "Password is missing"
			utils.RespondWithError(res, http.StatusBadRequest, error)
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
			utils.RespondWithError(res, http.StatusInternalServerError, error)
			return
		}

		// as we want to return user object in response, we want to hide password
		// todo ask why in Q&A
		user.Password = ""

		res.Header().Set("Content-Type", "application/json")
		utils.RespondWithJSON(res, user)
	}
}

// Login ...
func (c *Controller) Login(db *sql.DB) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var user models.User
		var jwt models.JWT
		var error models.Error

		json.NewDecoder(req.Body).Decode(&user)

		if user.Email == "" {
			error.Message = "Email is missing"
			utils.RespondWithError(res, http.StatusBadRequest, error)
			return
		}

		if user.Password == "" {
			error.Message = "Password is missing"
			utils.RespondWithError(res, http.StatusBadRequest, error)
			return
		}

		password := user.Password

		row := db.QueryRow("select * from users where email=$1", user.Email)
		err := row.Scan(&user.ID, &user.Email, &user.Password)

		if err != nil {
			if err == sql.ErrNoRows {
				error.Message = "User does not exist"
				utils.RespondWithError(res, http.StatusBadRequest, error)
				return
			} else {
				log.Fatal(err)
			}
		}

		hashedPassword := user.Password
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			error.Message = "Password is not valid"
			utils.RespondWithError(res, http.StatusBadRequest, error)
			return
		}

		token, err := utils.GenerateToken(user)
		if err != nil {
			log.Fatal(err)
		}

		res.WriteHeader(http.StatusOK)
		jwt.Token = token
		utils.RespondWithJSON(res, jwt)

	}
}

// TokenVerifyMiddleware ...
func (c *Controller) TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	secret := os.Getenv("SECRET")
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		var errorObject models.Error
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
				utils.RespondWithError(res, http.StatusBadRequest, errorObject)
				return
			}

			if token.Valid {
				next.ServeHTTP(res, req)
			} else {
				errorObject.Message = err.Error()
				utils.RespondWithError(res, http.StatusUnauthorized, errorObject)
				return
			}

		} else {
			errorObject.Message = "Invalid token"
			utils.RespondWithError(res, http.StatusUnauthorized, errorObject)
			return
		}
	})
}
