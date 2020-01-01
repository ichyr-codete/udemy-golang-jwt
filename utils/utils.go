package utils

import (
	"encoding/json"
	"net/http"

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
