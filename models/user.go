package models

import (
    // "fmt"
    "time"
    "database/sql"
    _ "github.com/lib/pq"
    // "github.com/jmoiron/sqlx"
)

type User struct {
    Id int64 `json:"id" db:"id"`
    Email string `json:"email" db:"email"`
    Password sql.NullString `json:"-" db:"password"`
    Disabled bool `json:"disabled" db:"disabled"`
    CreatedAt time.Time `json:"created_at" db:"created_at"`
    UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// UserExists checks if an email exists in the database
func (db *DB) UserExists(email string) (bool, error) {
    result := struct {Count int}{}
    query := `SELECT count(*) as count FROM "user" WHERE email=$1`
    err := db.Get(&result, query, email)
    if err != nil {
        return false, err
    }
    return result.Count > 0, nil
}

// GetUserByEmail gets the user model by email.
func (db *DB) GetUserByEmail(email string) (*User, error) {
    user := User{}
    err := db.Get(&user, `SELECT * FROM "user" WHERE email=$1`, email)
    if err != nil {
        return nil, err
    }
    return &user, nil
}

// CreateUser creates the user in the database.
func (db *DB) CreateUser(u *User) error {
    query := `INSERT INTO "user" (email, password, created_at, updated_at) VALUES (:email, :password, :created_at, :updated_at)`
    _, err := db.NamedExec(query, u)
    if err != nil {
        return err
    }
    return nil
}