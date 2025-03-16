package repository

import (
	"accesscontrolapi/config"
	"accesscontrolapi/internal/models"
	"fmt"
)

func GetAllAccessControls() ([]models.AccessControl, error) {
	var accessControls []models.AccessControl
	query := `SELECT * FROM access_manager.data_access_control`
	err := config.DB.Select(&accessControls, query)
	return accessControls, err
}

func UpdateAccessControl(id int, ac models.AccessControl) error {
	query := `
		UPDATE access_manager.data_access_control 
		SET "ProjectKey" = :ProjectKey, data_access_type = :data_access_type, delay_range = :delay_range
		WHERE rid = :rid;
	`
	params := map[string]interface{}{
		"ProjectKey":     ac.ProjectKey,
		"data_access_type": ac.DataAccessType,
		"delay_range":    ac.DelayRange,
		"rid":            id,
	}

	_, err := config.DB.NamedExec(query, params)
	if err != nil {
		fmt.Println("Error updating access control record:", err)
	}

	return err
}
