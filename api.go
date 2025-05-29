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

// Models
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

type Comment struct {
	ID        int       `json:"id"`
	PostID    int       `json:"post_id"`
	AuthorID  int       `json:"author_id"`
	Author    string    `json:"author,omitempty"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// Database
var db *sql.DB

// JWT Secret - will be loaded from environment
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

	// Build connection string from environment variables
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	sslmode := os.Getenv("DB_SSLMODE")

	// Validate required environment variables
	if user == "" || password == "" || dbname == "" {
		log.Fatal("Required environment variables missing: DB_USER, DB_PASSWORD, DB_NAME")
	}

	// Set defaults if not provided
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
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
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

// Utility functions
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

// User handlers
func registerHandler(w http.ResponseWriter, r *http.Request) {
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

func getPostsHandler(w http.ResponseWriter, r *http.Request) {
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
	// Set content type to HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// HTML template for the home page
	htmlTemplate := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog API - Home</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            padding: 60px 0;
            color: white;
        }
        
        .header h1 {
            font-size: 3.5rem;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header p {
            font-size: 1.3rem;
            opacity: 0.9;
            margin-bottom: 40px;
        }
        
        .content {
            background: white;
            border-radius: 15px;
            padding: 40px;
            margin: 40px 0;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .api-endpoints {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 30px;
            margin-top: 40px;
        }
        
        .endpoint {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            border-left: 5px solid #667eea;
            transition: transform 0.2s ease;
        }
        
        .endpoint:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .endpoint h3 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.3rem;
        }
        
        .method {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .get { background: #28a745; color: white; }
        .post { background: #007bff; color: white; }
        .put { background: #ffc107; color: black; }
        .delete { background: #dc3545; color: white; }
        
        .endpoint-url {
            font-family: 'Courier New', monospace;
            background: #e9ecef;
            padding: 8px;
            border-radius: 5px;
            margin: 10px 0;
            word-break: break-all;
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 25px;
            margin: 40px 0;
        }
        
        .feature {
            text-align: center;
            padding: 30px 20px;
        }
        
        .feature-icon {
            font-size: 3rem;
            margin-bottom: 20px;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: white;
            opacity: 0.8;
        }
        
        .status-badge {
            display: inline-block;
            background: #28a745;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9rem;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Blog API</h1>
            <p>A powerful RESTful API for managing blog posts with PostgreSQL</p>
            <span class="status-badge">✅ API Status: Online</span>
        </div>
        
        <div class="content">
            <h2>Welcome to the Blog API</h2>
            <p>This API provides a complete solution for managing blog posts with features like creating, reading, updating, deleting posts, and managing likes. Built with Go and PostgreSQL for optimal performance and reliability.</p>
            
            <div class="features">
                <div class="feature">
                    <div class="feature-icon">📝</div>
                    <h3>Post Management</h3>
                    <p>Create, read, update, and delete blog posts with ease</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">👍</div>
                    <h3>Likes System</h3>
                    <p>Increment and decrement likes on posts with atomic operations</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">🗄️</div>
                    <h3>PostgreSQL</h3>
                    <p>Robust database with migrations and data integrity</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">⚡</div>
                    <h3>High Performance</h3>
                    <p>Built with Go for speed and concurrent request handling</p>
                </div>
            </div>
            
            <h2>API Endpoints</h2>
            <div class="api-endpoints">
                <div class="endpoint">
                    <h3>Get All Posts</h3>
                    <span class="method get">GET</span>
                    <div class="endpoint-url">/posts</div>
                    <p>Retrieve all blog posts with their like counts</p>
                </div>
                
                <div class="endpoint">
                    <h3>Get Single Post</h3>
                    <span class="method get">GET</span>
                    <div class="endpoint-url">/posts/{id}</div>
                    <p>Retrieve a specific post by its ID</p>
                </div>
                
                <div class="endpoint">
                    <h3>Create Post</h3>
                    <span class="method post">POST</span>
                    <div class="endpoint-url">/posts</div>
                    <p>Create a new blog post with title and content</p>
                </div>
                
                <div class="endpoint">
                    <h3>Update Post</h3>
                    <span class="method put">PUT</span>
                    <div class="endpoint-url">/posts/{id}</div>
                    <p>Update an existing post's title or content</p>
                </div>
                
                <div class="endpoint">
                    <h3>Delete Post</h3>
                    <span class="method delete">DELETE</span>
                    <div class="endpoint-url">/posts/{id}</div>
                    <p>Permanently delete a blog post</p>
                </div>
                
                <div class="endpoint">
                    <h3>Like Post</h3>
                    <span class="method post">POST</span>
                    <div class="endpoint-url">/posts/like?id={post_id}</div>
                    <p>Increment the like count for a specific post</p>
                </div>
                
                <div class="endpoint">
                    <h3>Unlike Post</h3>
                    <span class="method post">POST</span>
                    <div class="endpoint-url">/posts/unlike?id={post_id}</div>
                    <p>Decrement the like count for a specific post</p>
                </div>
            </div>
            
            <h2>Getting Started</h2>
            <p>To interact with this API, you can use tools like <strong>curl</strong>, <strong>Postman</strong>, or any HTTP client. All endpoints return JSON responses (except this home page).</p>
            
            <h3>Example Usage:</h3>
            <div class="endpoint-url">
                curl -X GET http://localhost:8080/posts<br>
                curl -X POST http://localhost:8080/posts/like?id=1<br>
                curl -X POST -H "Content-Type: application/json" -d '{"title":"Hello World","content":"My first post"}' http://localhost:8080/posts
            </div>
        </div>
        
        <div class="footer">
            <p>&copy; 2025 Blog API - Built with ❤️ using Go & PostgreSQL</p>
        </div>
    </div>
</body>
</html>`

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
	r.HandleFunc("/api/register/", registerHandler).Methods("POST")
	r.HandleFunc("/api/login/", loginHandler).Methods("POST")
	r.HandleFunc("/api/posts/", getPostsHandler).Methods("GET")
	r.HandleFunc("/", homeHandler).
		r.HandleFunc("/api/posts/{id/}", getPostHandler).Methods("GET")

	// Protected routes
	r.HandleFunc("/api/posts/", authMiddleware(createPostHandler)).Methods("POST")
	r.HandleFunc("/api/posts/{id}/", authMiddleware(updatePostHandler)).Methods("PUT")
	r.HandleFunc("/api/posts/{id}/", authMiddleware(deletePostHandler)).Methods("DELETE")

	// Add CORS middleware
	handler := corsMiddleware(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server starting on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
