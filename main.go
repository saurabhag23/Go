/*package main

import (
	"encoding/json"
	"net/http"
	//"time"
	"log"
	"github.com/didip/tollbooth/v6"
)

func main() {

	lmt := tollbooth.NewLimiter(2, nil) // 2 request per second

	apiLimiter := tollbooth.NewLimiter(7, nil) // Allow 7 requests per second for the API

	message := map[string]string{"error": "Rate limit exceeded. Please try again later."}

	messageBytes, _ := json.Marshal(message)

	lmt.SetMessageContentType("application/json")
	lmt.SetMessage(string(messageBytes))
	apiLimiter.SetMessageContentType("application/json")
	apiLimiter.SetMessage(string(messageBytes))

	//apiLimiter.SetMethods([]string{"POST"})

	http.Handle("/", loggingMiddleware(tollbooth.LimitFuncHandler(lmt, homeHandler)))
	http.Handle("/check", loggingMiddleware(tollbooth.LimitFuncHandler(lmt, homeHandler2)))
	http.Handle("/api/data1", loggingMiddleware(tollbooth.LimitFuncHandler(apiLimiter, apiDataHandler1)))
	http.Handle("/api/data2", loggingMiddleware(tollbooth.LimitFuncHandler(apiLimiter, apiDataHandler2)))
	http.Handle("/api/data3", loggingMiddleware(tollbooth.LimitFuncHandler(apiLimiter, basicAuthMiddleware("admin", "password", apiDataHandler2))))

	println("Starting server on :8086...")
	if err := http.ListenAndServe(":8086", nil); err != nil {
		println(err.Error())
	}


}
/*
func validatePath(next http.Handler, validPaths []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for _, validPath := range validPaths {
			if path == validPath {
				next.ServeHTTP(w, r)
				return
			}
		}
		// If the path is not in the list of valid paths, return a 404 response
		http.NotFound(w, r)
	}
}*/

/*
	func loggingMiddleware(next http.Handler) http.Handler {
	    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	        log.Printf("Received request on %s from %s", r.URL.Path, r.RemoteAddr)
	        next.ServeHTTP(w, r)
	    })
	}

	func homeHandler(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello Friday!"))
	}

	func homeHandler2(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello US!"))
	}

	func apiDataHandler1(w http.ResponseWriter, r *http.Request) {
	    w.Write([]byte("This is some API data 1."))
	}

	func apiDataHandler2(w http.ResponseWriter, r *http.Request) {
	    w.Write([]byte("This is some API data 2."))
	}

	func basicAuthMiddleware(username, password string, next http.HandlerFunc) http.HandlerFunc {
	    return func(w http.ResponseWriter, r *http.Request) {
	        user, pass, ok := r.BasicAuth()
	        if !ok || user != username || pass != password {
	            w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
	            http.Error(w, "Unauthorized", http.StatusUnauthorized)
	            return
	        }
	        next(w, r)
	    }
	}

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

type User struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type RateLimiter struct {
	requests map[string]int
	reset    map[string]time.Time
	lock     sync.Mutex
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		requests: make(map[string]int),
		reset:    make(map[string]time.Time),
		lock:     sync.Mutex{},
	}
}

// LogRateLimitDetails logs the current state for a given API key
func (rl *RateLimiter) LogRateLimitDetails(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Authorization")

		rl.lock.Lock()
		requests := rl.requests[key]
		resetTime := rl.reset[key]
		rl.lock.Unlock()

		// Log the information without directly printing the struct that includes a mutex
		fmt.Printf("Authorization Key: %s, Requests: %d, Resets at: %v\n", key, requests, resetTime)
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) Limit(rate int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("Authorization")

			rl.lock.Lock()
			defer rl.lock.Unlock()

			if _, exists := rl.requests[key]; !exists {
				rl.reset[key] = time.Now().Add(window)
			}

			if time.Now().After(rl.reset[key]) {
				rl.requests[key] = 0
				rl.reset[key] = time.Now().Add(window)
			}

			if rl.requests[key] >= rate {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			rl.requests[key]++

			next.ServeHTTP(w, r)
		})
	}
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	users := []User{
		{ID: 1, Name: "Alice"},
		{ID: 2, Name: "Bob"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func main() {
	r := mux.NewRouter()
	rateLimiter := NewRateLimiter()

	// First log the details, then apply the rate limiting
	r.Use(rateLimiter.LogRateLimitDetails)
	r.Use(rateLimiter.Limit(10, time.Minute))

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, world!")
	})

	r.HandleFunc("/api/v1/users", usersHandler)

	http.ListenAndServe(":8080", r)
}

package main

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
)

func generateSecretKey(length int) (string, error) {
    b := make([]byte, length)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}

func main() {
    secretKey, err := generateSecretKey(32) // 32 bytes = 256 bits
    if err != nil {
        panic(err)
    }
    fmt.Println("Your secret key:", secretKey)
}
*/


package main

import (
	"fmt"
	"net/http"
	"time"
	"github.com/gorilla/mux"
	"local/go/src/saurabhagrawal/Desktop/Go/middleware"
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
