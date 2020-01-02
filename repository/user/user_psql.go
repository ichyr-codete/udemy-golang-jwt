package userRepository

import (
	"database/sql"
	"log"

	"github.com/ichyr-codete/udemy-golang-jwt/models"
)

type UserRepository struct{}

func logFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func (u UserRepository) Signup(db *sql.DB, user models.User) models.User {
	insertStatement := "insert into users (email, password) values($1, $2) returning id;"
	err := db.QueryRow(insertStatement, user.Email, user.Password).Scan(&user.ID)

	logFatal(err)

	user.Password = ""
	return user
}

func (u UserRepository) Login(db *sql.DB, user models.User) (models.User, error) {
	row := db.QueryRow("select * from users where email=$1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		return user, err
	}

	return user, nil
}
