package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"accesscontrolapi/config"
	"accesscontrolapi/routes"
	"github.com/rs/cors"
)

func main() {
	// Load configuration from YAML
	err := config.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Connect to the database
	err = config.ConnectDB()
	if err != nil {
		log.Fatalf("Database connection failed: %v", err)
	}

	// Start API server
	r := mux.NewRouter()
	routes.RegisterRoutes(r)


	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:4200"}, // ✅ Allow Angular
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})

	handler := corsHandler.Handler(r)



	port := config.Config.Server.Port
	fmt.Printf("Server running on port %d\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), handler))
}