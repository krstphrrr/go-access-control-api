package routes

import (
	"github.com/gorilla/mux"
	"accesscontrolapi/internal/handlers"
)

func RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/api/access-control", handlers.GetAccessControls).Methods("GET")
	r.HandleFunc("/api/access-control/{id}", handlers.UpdateAccessControl).Methods("PUT")
}
