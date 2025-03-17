package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"accesscontrolapi/internal/models"
	"accesscontrolapi/internal/services"
	"accesscontrolapi/pkg"

	"github.com/gorilla/mux"
)

func GetAccessControls(w http.ResponseWriter, r *http.Request) {
	// Debugging: Log Authorization header
	authHeader := r.Header.Get("Authorization")
	fmt.Println("Authorization Header:", authHeader)

	if authHeader == "" {
		http.Error(w, "Unauthorized: missing authorization header", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		http.Error(w, "Unauthorized: invalid token format", http.StatusUnauthorized)
		return
	}

	// Debugging: Log extracted token
	// fmt.Println("Extracted Token:", token)

	claims, err := auth.VerifyJWTWithCognito(token)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Debugging: Log Cognito claims
	// fmt.Println("JWT Claims:", claims)

	// Restrict access based on user group
	groups, ok := claims["cognito:groups"].([]interface{})
	if !ok || len(groups) == 0 {
		http.Error(w, "Forbidden: User not in any group", http.StatusForbidden)
		return
	}

	isAdmin := false
	for _, group := range groups {
		if group == "Admin" {
			isAdmin = true
			break
		}
	}

	if !isAdmin {
		http.Error(w, "Forbidden: Access denied", http.StatusForbidden)
		return
	}

	// Fetch and return access control records
	accessControls, err := services.FetchAllAccessControls()
	if err != nil {
		http.Error(w, "Failed to fetch records", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(accessControls)
}

func UpdateAccessControl(w http.ResponseWriter, r *http.Request) {
	// Extract `rid` from URL
	vars := mux.Vars(r)
	ridStr := vars["id"]
	fmt.Println("Received ID from request:", ridStr) // ✅ Debugging

	rid, err := strconv.Atoi(ridStr)
	if err != nil {
		http.Error(w, "Invalid record ID", http.StatusBadRequest)
		return
	}

	// Parse Request Body
	var updatedAccessControl models.AccessControl
	err = json.NewDecoder(r.Body).Decode(&updatedAccessControl)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	fmt.Printf("Updating record ID %d with data: %+v\n", rid, updatedAccessControl) // ✅ Debugging

	// Perform update
	err = services.UpdateAccessControl(rid, updatedAccessControl)
	if err != nil {
		http.Error(w, "Failed to update record", http.StatusInternalServerError)
		return
	}

	// Respond with success
	w.Header().Set("Content-Type", "application/json") // ✅ Ensure JSON response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Access control record updated successfully"})

}
