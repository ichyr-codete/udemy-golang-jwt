package utils

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/ichyr-codete/udemy-golang-jwt/models"
)

// RespondWithError ...
func RespondWithError(res http.ResponseWriter, status int, error models.Error) {
	res.WriteHeader(status)
	json.NewEncoder(res).Encode(error)
}

// RespondWithJSON ...
func RespondWithJSON(res http.ResponseWriter, data interface{}) {
	json.NewEncoder(res).Encode(data)
}

// GenerateToken ...
func GenerateToken(user models.User) (string, error) {
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
