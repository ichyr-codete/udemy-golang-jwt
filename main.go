package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ichyr-codete/udemy-golang-jwt/controllers"
	"github.com/ichyr-codete/udemy-golang-jwt/driver"
	"github.com/subosito/gotenv"
)

var db *sql.DB

func init() {
	gotenv.Load()
}

func main() {

	db = driver.ConnectDB()
	controller := controllers.Controller{}

	router := mux.NewRouter()

	router.HandleFunc("/signup", controller.Signup(db)).Methods("POST")
	router.HandleFunc("/login", controller.Login(db)).Methods("POST")
	router.HandleFunc("/protected", controller.TokenVerifyMiddleware(controller.ProtectedEndpoint())).Methods("GET")

	log.Println("Listening on port 8000...")
	err := http.ListenAndServe(":8000", router)
	// application will exit if some error emerged from server start up
	log.Fatal(err)
}
