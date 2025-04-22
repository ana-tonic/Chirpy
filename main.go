package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

type parameters struct {
	Body string `json:"body"`
}

type returnVals struct {
	Valid bool `json:"valid"`
}

func main() {
	var apiConfig apiConfig

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

	h3 := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		apiConfig.fileserverHits.Store(0)
		w.WriteHeader(http.StatusOK)
	}

	h4 := func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
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

		respBody := returnVals{
			Valid: true,
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

	mux.HandleFunc("POST /api/validate_chirp", h4)

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}
