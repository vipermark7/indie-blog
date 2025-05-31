package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  string    `json:"password,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Post struct {
	ID        int       `json:"id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	AuthorID  int       `json:"author_id"`
	Author    string    `json:"author,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

var db *sql.DB

var jwtSecret []byte

// Claims struct for JWT
type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func initDBWithRetry() {
	var err error
	maxRetries := 5
	retryDelay := time.Second * 2

	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	sslmode := os.Getenv("DB_SSLMODE")

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

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)

	fmt.Printf("Attempting to connect to: host=%s port=%s user=%s dbname=%s\n",
		host, port, user, dbname)

	// Try to connect with retries
	for i := 0; i < maxRetries; i++ {
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

		// Success!
		log.Println("Database connected successfully")
		createTables()
		return
	}
	log.Fatal("Failed to connect to database after", maxRetries, "attempts")
}

func createTables() {
	// Users table
	userTable := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(100) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`

	// Posts table
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

// Middleware
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Bearer token required", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add user info to request context
		r.Header.Set("X-User-ID", strconv.Itoa(claims.UserID))
		r.Header.Set("X-Username", claims.Username)

		next(w, r)
	}
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateToken(userID int, username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}
func registerUserForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	html, err := os.ReadFile("register.html")
	if err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		log.Printf("Error reading template file register.html: %v", err)
	}

	htmlTemplate := string(html)

	tmpl, err := template.New("home").Parse(htmlTemplate)
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		log.Printf("Template parsing error: %v", err)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
		return
	}
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	log.Printf("Method: %s, URL: %s", r.Method, r.URL.Path)
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if user.Username == "" || user.Email == "" || user.Password == "" {
		respondError(w, http.StatusBadRequest, "Username, email, and password are required")
		return
	}

	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	query := `INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, created_at`
	err = db.QueryRow(query, user.Username, user.Email, hashedPassword).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			respondError(w, http.StatusConflict, "Username or email already exists")
			return
		}
		respondError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	// empty string should be omitted in JSON response (`json:"password,omitempty"`)
	user.Password = ""
	respondJSON(w, http.StatusCreated, user)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	var user User
	var passwordHash string
	query := `SELECT id, username, email, password_hash, created_at FROM users WHERE username = $1`
	err := db.QueryRow(query, loginReq.Username).Scan(&user.ID, &user.Username, &user.Email, &passwordHash, &user.CreatedAt)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if !checkPassword(loginReq.Password, passwordHash) {
		respondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	token, err := generateToken(user.ID, user.Username)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	response := LoginResponse{
		Token: token,
		User:  user,
	}

	respondJSON(w, http.StatusOK, response)
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.Atoi(r.Header.Get("X-User-ID"))

	var post Post
	if err := json.NewDecoder(r.Body).Decode(&post); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if post.Title == "" || post.Content == "" {
		respondError(w, http.StatusBadRequest, "Title and content are required")
		return
	}

	query := `INSERT INTO posts (title, content, author_id) VALUES ($1, $2, $3) RETURNING id, created_at, updated_at`
	err := db.QueryRow(query, post.Title, post.Content, userID).Scan(&post.ID, &post.CreatedAt, &post.UpdatedAt)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create post")
		return
	}

	post.AuthorID = userID
	respondJSON(w, http.StatusCreated, post)
}

func postsIndexHandler(w http.ResponseWriter, r *http.Request) {
	query := `
		SELECT p.id, p.title, p.content, p.author_id, u.username, p.created_at, p.updated_at 
		FROM posts p 
		JOIN users u ON p.author_id = u.id 
		ORDER BY p.created_at DESC`

	rows, err := db.Query(query)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch posts")
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.AuthorID, &post.Author, &post.CreatedAt, &post.UpdatedAt)
		if err != nil {
			continue
		}
		posts = append(posts, post)
	}

	respondJSON(w, http.StatusOK, posts)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	html, err := os.ReadFile("homepage.html")
	if err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		log.Printf("Error reading template file homepage.html: %v", err)
	}

	htmlTemplate := string(html)

	// Parse and execute the template
	tmpl, err := template.New("home").Parse(htmlTemplate)
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		log.Printf("Template parsing error: %v", err)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
		return
	}
}

func getPostHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	postID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid post ID")
		return
	}

	var post Post
	query := `
		SELECT p.id, p.title, p.content, p.author_id, u.username, p.created_at, p.updated_at 
		FROM posts p 
		JOIN users u ON p.author_id = u.id 
		WHERE p.id = $1`

	err = db.QueryRow(query, postID).Scan(&post.ID, &post.Title, &post.Content, &post.AuthorID, &post.Author, &post.CreatedAt, &post.UpdatedAt)
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "Post not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch post")
		return
	}

	respondJSON(w, http.StatusOK, post)
}

func updatePostHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	postID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid post ID")
		return
	}

	userID, _ := strconv.Atoi(r.Header.Get("X-User-ID"))

	var post Post
	if err := json.NewDecoder(r.Body).Decode(&post); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// Check if user owns the post
	var authorID int
	err = db.QueryRow("SELECT author_id FROM posts WHERE id = $1", postID).Scan(&authorID)
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "Post not found")
		return
	}
	if authorID != userID {
		respondError(w, http.StatusForbidden, "You can only update your own posts")
		return
	}

	query := `UPDATE posts SET title = $1, content = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING updated_at`
	err = db.QueryRow(query, post.Title, post.Content, postID).Scan(&post.UpdatedAt)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update post")
		return
	}

	post.ID = postID
	respondJSON(w, http.StatusOK, post)
}

func deletePostHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	postID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid post ID")
		return
	}

	userID, _ := strconv.Atoi(r.Header.Get("X-User-ID"))

	// Check if user owns the post
	var authorID int
	err = db.QueryRow("SELECT author_id FROM posts WHERE id = $1", postID).Scan(&authorID)
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "Post not found")
		return
	}
	if authorID != userID {
		respondError(w, http.StatusForbidden, "You can only delete your own posts")
		return
	}

	_, err = db.Exec("DELETE FROM posts WHERE id = $1", postID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete post")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"message": "Post deleted successfully"})
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	jwtSecretStr := os.Getenv("JWT_SECRET")
	if jwtSecretStr == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}
	jwtSecret = []byte(jwtSecretStr)

	initDBWithRetry()
	defer db.Close()

	r := mux.NewRouter()
	r.StrictSlash(true)
	// Public routes
	r.HandleFunc("/register", registerUserForm)
	r.HandleFunc("/api/register", registerUser).Methods("POST")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")
	//TODO: implement Discover functionality, showing other people's blogs, or some sample blogs
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/api/posts/{id/}", getPostHandler).Methods("GET")

	// Protected routes
	r.HandleFunc("/api/posts", authMiddleware(postsIndexHandler)).Methods("GET")
	r.HandleFunc("/api/posts", authMiddleware(createPostHandler)).Methods("POST")
	r.HandleFunc("/api/posts/{id}", authMiddleware(updatePostHandler)).Methods("PUT")
	r.HandleFunc("/api/posts/{id}", authMiddleware(deletePostHandler)).Methods("DELETE")

	// Add CORS middleware
	handler := corsMiddleware(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server starting on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
