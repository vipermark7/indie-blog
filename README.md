# indie-blog

To run locally, ensure that you've installed Go, and that PostgreSQL is running. After that, running `go run api.go` from the root folder for the project should get you up and running. Go should automatically download and install the packages it needs, regardless of platform :)

# Current API endpoints:
## Public routes
	"/api/register    ("POST")
	"/api/login       ("POST")
	"/api/post        ("GET")
	"/api/posts/{id}" ("GET")

## Protected routes
	"/api/posts       ("POST")
	"/api/posts/{id}" ("PUT")
	"/api/posts/{id}" ("DELETE")