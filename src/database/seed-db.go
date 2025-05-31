package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

var host = os.Getenv("DB_HOST")
var port = os.Getenv("DB_PORT")
var user = os.Getenv("DB_USER")
var dbname = os.Getenv("DB_NAME")

func buildConnectionString(host string, port string, user string) string {
	password := os.Getenv("DB_PASSWORD")
	sslmode := os.Getenv("DB_SSLMODE")
	dbname := os.Getenv("DB_NAME")

	if user == "" || password == "" || dbname == "" {
		log.Fatal("Required environment variables missing: DB_USER, DB_PASSWORD, DB_NAME")
	}

	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "5432"
	}
	if sslmode == "" {
		sslmode = "disable"
	}

	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode,
	)
}

func InitDBWithRetry() {
	var err error
	maxRetries := 5
	retryDelay := time.Second * 2

	connStr := buildConnectionString(host, port, user)

	fmt.Printf("Attempting to connect to: host=%s port=%s user=%s dbname=%s\n",
		host, port, user, dbname)

	for i := range maxRetries {
		db, err = sql.Open("postgres", connStr)
		if err != nil {
			log.Printf("Attempt %d: Failed to open database connection: %v", i+1, err)
			time.Sleep(retryDelay)
			continue
		}

		// Test the connection
		if err = db.Ping(); err != nil {
			log.Printf("Attempt %d: Failed to ping database: %v", i+1, err)
			db.Close()
			time.Sleep(retryDelay)
			continue
		}

		log.Println("Database connected successfully")
		createTables()
		return
	}
	log.Fatal("Failed to connect to database after", maxRetries, "attempts")
}

func createTables() {
	userTable := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(100) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`

	postTable := `
	CREATE TABLE IF NOT EXISTS posts (
		id SERIAL PRIMARY KEY,
		title VARCHAR(255) NOT NULL,
		content TEXT NOT NULL,
		author_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`

	tables := []string{userTable, postTable}
	for _, table := range tables {
		if _, err := db.Exec(table); err != nil {
			log.Fatal("Failed to create table:", err)
		}
	}
}

func seedDatabase(db *sql.DB) error {
	password := "password"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	query := `
        INSERT INTO users (username, email, password_hash, created_at, updated_at) 
        VALUES ($1, $2, $3, NOW(), NOW()) 
        ON CONFLICT (email) DO NOTHING`

	_, err = db.Exec(query, "testuser", "test@example.com", string(hashedPassword))
	if err != nil {
		return err
	}

	log.Println("Test user seeded successfully")
	return nil
}

func main() {
	InitDBWithRetry()

	// Seed the database
	if err := seedDatabase(db); err != nil {
		log.Fatal("Failed to seed database:", err)
	}
}
