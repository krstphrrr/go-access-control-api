package services

import (
	"accesscontrolapi/internal/models"
	"accesscontrolapi/internal/repository"
	"fmt"
)

func FetchAllAccessControls() ([]models.AccessControl, error) {
	return repository.GetAllAccessControls()
}

func UpdateAccessControl(id int, ac models.AccessControl) error {
	fmt.Printf("Updating record ID %d with data: %+v\n", id, ac)
	return repository.UpdateAccessControl(id, ac)
}