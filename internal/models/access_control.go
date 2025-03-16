package models

type AccessControl struct {
	ID             int    `db:"rid" json:"rid"`
	ProjectKey     string `db:"ProjectKey" json:"project_key"`
	DataAccessType string `db:"data_access_type" json:"data_access_type"`
	DelayRange     string `db:"delay_range" json:"delay_range"`
}