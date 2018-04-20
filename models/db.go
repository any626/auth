package models

import (
    "fmt"
    "../config"
    // "database/sql"
    _ "github.com/lib/pq"
    "github.com/jmoiron/sqlx"
)

type Datastore interface {
    GetUserByEmail() (*User, error)
}

type DB struct {
    *sqlx.DB
}

// NewDB initiates a new db connection
func NewDB(c config.Config) (*DB, error) {
    db, err := sqlx.Connect("postgres", createDNS(c))
    if err != nil {
        return nil, err
    }
    return &DB{db}, nil
}

// Created the connection string for the database.
func createDNS(c config.Config) string {
    return fmt.Sprintf("user=%s dbname=%s port=%d host=%s sslmode=%s password=%s", c.Username, c.Database, c.Port, c.Host, c.Sslmode, c.Password)
}