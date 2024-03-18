package main

import (
	"fmt"
	"net/http"
	"time"
	"github.com/gorilla/mux"
	"github.com/saurabhag23/Go/middleware"
)

func main() {
	r := mux.NewRouter()

	// Initialize and use the IP Whitelist middleware
	r.Use(middleware.IPWhitelistMiddleware)

	// Initialize and use the Rate Limiting middleware
	signingKey := []byte("7F0-1l-kDdEFdC4djjVNxUiQKsjp6ekIrKQbYrqeSd4=") // Ensure to use your actual JWT signing secret
	rateLimiter := middleware.NewRateLimiter()
	r.Use(rateLimiter.Limit(signingKey, 5, 10, time.Minute))

	// Whitelist management endpoints
	r.HandleFunc("/whitelist/add", middleware.AddIPHandler).Methods("POST")
	r.HandleFunc("/whitelist/remove", middleware.RemoveIPHandler).Methods("POST")

	// Rate Limiter user endpoint
	r.HandleFunc("/api/v1/users", middleware.UsersHandler).Methods("GET")

	// A sample endpoint to demonstrate both middlewares in action
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, world with middleware!"))
	})

	fmt.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", r)
}
