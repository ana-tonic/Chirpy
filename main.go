package main

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ana-tonic/Chirpy/internal/auth"
	"github.com/ana-tonic/Chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	tokenSecret    string
	platform       string
	polkaKey       string
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

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userResponse struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
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

type refreshResponse struct {
	Token string `json:"token"`
}

type polkaWebhookRequest struct {
	Event string `json:"event"`
	Data  struct {
		UserID uuid.UUID `json:"user_id"`
	} `json:"data"`
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
	apiConfig.platform = platform

	tokenSecret := os.Getenv("TOKEN_SECRET")
	apiConfig.tokenSecret = tokenSecret

	polkaKey := os.Getenv("POLKA_KEY")
	apiConfig.polkaKey = polkaKey

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

		if apiConfig.platform != "dev" {
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

	postUserHandler := func(w http.ResponseWriter, r *http.Request) {
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

	postChirpHandler := func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request headers: %v", r.Header)
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error getting bearer token: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		userID, err := auth.ValidateJWT(token, apiConfig.tokenSecret)
		if err != nil {
			log.Printf("Error validating JWT: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		params := chirpRequest{}
		err = decoder.Decode(&params)
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
			UserID: userID,
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

	getChirpsHandler := func(w http.ResponseWriter, r *http.Request) {
		authorID := r.URL.Query().Get("author_id")
		var chirps []database.Chirp
		var err error

		if authorID != "" {
			authorIDUUID, err := uuid.Parse(authorID)
			if err != nil {
				log.Printf("Error parsing author ID: %s", err)
				w.WriteHeader(400)
				w.Write([]byte("Invalid author ID"))
				return
			}
			chirps, err = apiConfig.db.GetChirpsByAuthorID(r.Context(), authorIDUUID)
		} else {
			chirps, err = apiConfig.db.GetChirps(r.Context())
		}

		if err != nil {
			log.Printf("Error getting chirps: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		sortOrder := r.URL.Query().Get("sort")
		if sortOrder == "desc" {
			slices.SortFunc(chirps, func(i, j database.Chirp) int {
				if i.CreatedAt.After(j.CreatedAt) {
					return -1
				}
				return 1
			})
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

	getChirpHandler := func(w http.ResponseWriter, r *http.Request) {
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

	loginHandler := func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		params := loginRequest{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		user, err := apiConfig.db.GetUserByEmail(r.Context(), params.Email)
		if err != nil {
			log.Printf("Error getting user: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(params.Password))
		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		// Default expiration time is 1 hour
		expiresIn := time.Hour

		token, err := auth.MakeJWT(user.ID, apiConfig.tokenSecret, expiresIn)
		if err != nil {
			log.Printf("Error creating JWT: %s", err)
			w.WriteHeader(500)
			return
		}

		refreshToken, err := auth.MakeRefreshToken()
		if err != nil {
			log.Printf("Error creating refresh token: %s", err)
			w.WriteHeader(500)
			return
		}

		_, err = apiConfig.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     refreshToken,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
		})
		if err != nil {
			log.Printf("Error creating refresh token: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		dat, err := json.Marshal(userResponse{
			ID:           user.ID,
			CreatedAt:    user.CreatedAt.Time,
			UpdatedAt:    user.UpdatedAt.Time,
			Email:        user.Email,
			Token:        token,
			RefreshToken: refreshToken,
			IsChirpyRed:  user.IsChirpyRed.Bool,
		})
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Write(dat)
	}

	refreshHandler := func(w http.ResponseWriter, r *http.Request) {
		refreshToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error getting bearer token: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		token, err := apiConfig.db.GetRefreshToken(r.Context(), refreshToken)
		if err != nil {
			log.Printf("Error getting refresh token: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		// Check if token is revoked (RevokedAt is set)
		if token.RevokedAt.Valid {
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		// Check if token has expired
		if token.ExpiresAt.Before(time.Now().UTC()) {
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		userID, err := apiConfig.db.GetUserFromRefreshToken(r.Context(), token.Token)
		if err != nil {
			log.Printf("Error getting user: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		newToken, err := auth.MakeJWT(userID, apiConfig.tokenSecret, time.Hour)
		if err != nil {
			log.Printf("Error creating JWT: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		dat, err := json.Marshal(refreshResponse{
			Token: newToken,
		})
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Write(dat)
	}

	revokeHandler := func(w http.ResponseWriter, r *http.Request) {
		refreshToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error getting bearer token: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		err = apiConfig.db.RevokeRefreshToken(r.Context(), refreshToken)
		if err != nil {
			log.Printf("Error revoking refresh token: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		w.WriteHeader(204)
	}

	updateUserHandler := func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		params := userRequest{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error getting bearer token: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		userID, err := auth.ValidateJWT(token, apiConfig.tokenSecret)
		if err != nil {
			log.Printf("Error validating JWT: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing password: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		err = apiConfig.db.UpdateUser(r.Context(), database.UpdateUserParams{
			ID:             userID,
			Email:          params.Email,
			HashedPassword: string(hashedPassword),
		})

		if err != nil {
			log.Printf("Error updating user: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		user, err := apiConfig.db.GetUserByEmail(r.Context(), params.Email)
		if err != nil {
			log.Printf("Error getting user: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		userResponse := userResponse{
			ID:        user.ID,
			CreatedAt: user.CreatedAt.Time,
			UpdatedAt: user.UpdatedAt.Time,
			Email:     user.Email,
		}

		w.WriteHeader(200)
		dat, err := json.Marshal(userResponse)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Write(dat)
	}

	deleteChirpHandler := func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error getting bearer token: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		userID, err := auth.ValidateJWT(token, apiConfig.tokenSecret)
		if err != nil {
			log.Printf("Error validating JWT: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		chirpID := r.PathValue("id")
		chirpIDUUID, err := uuid.Parse(chirpID)
		if err != nil {
			log.Printf("Error parsing chirp ID: %s", err)
			w.WriteHeader(400)
			w.Write([]byte("Invalid chirp ID"))
			return
		}

		chirp, err := apiConfig.db.GetChirp(r.Context(), chirpIDUUID)
		if err != nil {
			log.Printf("Error getting chirp: %s", err)
			w.WriteHeader(404)
			w.Write([]byte("Chirp not found"))
			return
		}

		if chirp.UserID != userID {
			w.WriteHeader(403)
			w.Write([]byte("Forbidden"))
			return
		}

		err = apiConfig.db.DeleteChirp(r.Context(), chirpIDUUID)
		if err != nil {
			log.Printf("Error deleting chirp: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		w.WriteHeader(204)
	}

	polkaWebhookHandler := func(w http.ResponseWriter, r *http.Request) {
		apiKey, err := auth.GetAPIKey(r.Header)
		if err != nil {
			log.Printf("Error getting API key: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		if apiKey != apiConfig.polkaKey {
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		params := polkaWebhookRequest{}
		err = decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return
		}

		if params.Event != "user.upgraded" {
			w.WriteHeader(204)
			return
		}

		err = apiConfig.db.SetIsChirpyRed(r.Context(), database.SetIsChirpyRedParams{
			ID:          params.Data.UserID,
			IsChirpyRed: sql.NullBool{Bool: true, Valid: true},
		})
		if err != nil {
			switch err {
			case sql.ErrNoRows:
				w.WriteHeader(404)
				w.Write([]byte("User not found"))
				return
			default:
				w.WriteHeader(500)
				w.Write([]byte("Something went wrong"))
				return
			}
		}

		w.WriteHeader(204)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", h1)
	mux.HandleFunc("GET /admin/metrics", h2)
	mux.HandleFunc("POST /admin/reset", h3)
	mux.Handle("/app/", apiConfig.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	mux.HandleFunc("POST /api/chirps", postChirpHandler)
	mux.HandleFunc("GET /api/chirps", getChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{id}", getChirpHandler)
	mux.HandleFunc("DELETE /api/chirps/{id}", deleteChirpHandler)

	mux.HandleFunc("POST /api/users", postUserHandler)
	mux.HandleFunc("PUT /api/users", updateUserHandler)
	mux.HandleFunc("POST /api/login", loginHandler)
	mux.HandleFunc("POST /api/refresh", refreshHandler)
	mux.HandleFunc("POST /api/revoke", revokeHandler)
	mux.HandleFunc("POST /api/polka/webhooks", polkaWebhookHandler)
	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}
