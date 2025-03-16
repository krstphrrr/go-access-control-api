## test
### todo 
- docker workflow (compose + image)


```
go-access-control-api/
│── main.go                   # Entry point
│── config/                   
│   ├── config.go             # Configuration handling
│── internal/
│   ├── handlers/             # HTTP handlers
│   │   ├── access_control.go # Business logic for access control
│   ├── models/               # Database models
│   │   ├── access_control.go 
│   ├── repository/           # Database interactions
│   │   ├── access_control_repo.go 
│   ├── services/             # Business logic
│   │   ├── access_control_service.go 
│   ├── version/
│        ├── version.go       # Version control
│── routes/                   # API routes
│   ├── routes.go
│── pkg/                      # Utility packages (auth, logging)
│   ├── auth.go
│ 
│── go.mod                     # Go module file
```