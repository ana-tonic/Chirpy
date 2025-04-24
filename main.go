package main

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ana-tonic/Chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

type userRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

type chirpRequest struct {
	Body   string    `json:"body"`
	UserID uuid.UUID `json:"user_id"`
}

type chirpResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func main() {
	var apiConfig apiConfig

	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	dbQueries := database.New(db)

	apiConfig.db = dbQueries

	platform := os.Getenv("PLATFORM")

	h1 := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}

	h2 := func(w http.ResponseWriter, _ *http.Request) {
		tmpl, err := template.ParseFiles("metrics.html")
		if err != nil {
			http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		count := apiConfig.fileserverHits.Load()

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		err = tmpl.Execute(w, count)
		if err != nil {
			http.Error(w, "Execute error: "+err.Error(), http.StatusInternalServerError)
		}
	}

	h3 := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if platform != "dev" {
			w.WriteHeader(403)
			return
		}

		err := apiConfig.db.DeleteAllUsers(r.Context())
		if err != nil {
			log.Printf("Error deleting users: %s", err)
			w.WriteHeader(500)
			return
		}

		apiConfig.fileserverHits.Store(0)
		w.WriteHeader(http.StatusOK)
	}

	h5 := func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		params := userRequest{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing password: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		user, err := apiConfig.db.CreateUser(r.Context(), database.CreateUserParams{
			Email:          params.Email,
			HashedPassword: string(hashedPassword),
		})
		if err != nil {
			log.Printf("Error creating user: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		respBody := userResponse{
			ID:        user.ID,
			CreatedAt: user.CreatedAt.Time,
			UpdatedAt: user.UpdatedAt.Time,
			Email:     user.Email,
		}

		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write(dat)
	}

	h6 := func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		params := chirpRequest{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		if len(params.Body) > 140 {
			w.WriteHeader(400)
			w.Write([]byte("Chirp is too long"))
			return
		}

		bodyLower := strings.ToLower(params.Body)
		if strings.Contains(bodyLower, "kerfuffle") || strings.Contains(bodyLower, "sharbert") || strings.Contains(bodyLower, "fornax") {
			re := regexp.MustCompile(`(?i)\b(kerfuffle|sharbert|fornax)\b`)
			params.Body = re.ReplaceAllString(params.Body, "****")
		}

		chirp, err := apiConfig.db.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   params.Body,
			UserID: params.UserID,
		})
		if err != nil {
			log.Printf("Error creating chirp: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		respBody := chirpResponse{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		}
		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write(dat)
	}

	h7 := func(w http.ResponseWriter, r *http.Request) {
		chirps, err := apiConfig.db.GetChirps(r.Context())
		if err != nil {
			log.Printf("Error getting chirps: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		respBody := []chirpResponse{}
		for _, chirp := range chirps {
			respBody = append(respBody, chirpResponse{
				ID:        chirp.ID,
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserID:    chirp.UserID,
			})
		}
		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(dat)
	}

	h8 := func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		chirp, err := apiConfig.db.GetChirp(r.Context(), uuid.MustParse(id))
		if err != nil {
			switch err {
			case sql.ErrNoRows:
				w.WriteHeader(404)
				w.Write([]byte("Chirp not found"))
				return
			default:
				log.Printf("Error getting chirp: %s", err)
				w.WriteHeader(500)
				w.Write([]byte("Something went wrong"))
				return
			}
		}

		respBody := chirpResponse{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		}
		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(dat)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", h1)
	mux.HandleFunc("GET /admin/metrics", h2)
	mux.HandleFunc("POST /admin/reset", h3)
	mux.Handle("/app/", apiConfig.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	mux.HandleFunc("POST /api/chirps", h6)
	mux.HandleFunc("GET /api/chirps", h7)
	mux.HandleFunc("GET /api/chirps/{id}", h8)

	mux.HandleFunc("POST /api/users", h5)

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}
