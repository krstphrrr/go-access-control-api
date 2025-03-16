package config

import (
	"fmt"
	"log"
	"os"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // PostgreSQL driver
	"gopkg.in/yaml.v2"
)

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Name     string `yaml:"name"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type ServerConfig struct {
	Port int `yaml:"port"`
}

type AwsCognitoConfig struct {
	Region     string `yaml:"region"`
	UserPoolId string `yaml:"userPoolId"`
	ClientId   string `yaml:"clientId"`
	TokenType  string `yaml:"tokenType"`
}

type AppConfig struct {
	Server     ServerConfig    `yaml:"server"`
	Database   DatabaseConfig  `yaml:"database"`
	AwsCognito AwsCognitoConfig `yaml:"awsCognito"`
}

var Config AppConfig
var DB *sqlx.DB

func LoadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	err = yaml.Unmarshal(data, &Config)
	if err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}

	log.Println("Configuration loaded successfully")
	// ✅ Debug: Check if values are loaded correctly
	log.Printf("Loaded AWS Cognito Config: Region=%s, UserPoolId=%s", Config.AwsCognito.Region, Config.AwsCognito.UserPoolId)

	return nil
}

func ConnectDB() error {
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable",
		Config.Database.Host, Config.Database.Port, Config.Database.Name, Config.Database.User, Config.Database.Password)

	var err error
	DB, err = sqlx.Connect("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %v", err)
	}

	log.Println("Connected to database!")
	return nil
}
