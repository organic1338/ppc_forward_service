package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	ginSwagger "github.com/swaggo/gin-swagger"
	swaggerFiles "github.com/swaggo/files"
	_ "modernc.org/sqlite"

	"ppc_forward_service/docs"
)

// @title PPC Forward Service API
// @version 1.0
// @description Admin creates customers and forwards call info; customers fetch latest info per phone number.
// @BasePath /api/v1
// @securityDefinitions.apikey AdminKey
// @in header
// @name X-Admin-Key
// @securityDefinitions.apikey CustomerKey
// @in header
// @name X-API-Key

// Server wraps shared dependencies for handlers.
type Server struct {
	db       *sql.DB
	adminKey string
}

var phonePrefixes = []string{"+40", "0040", "40"}

func main() {
	adminKey := os.Getenv("ADMIN_API_KEY")
	if adminKey == "" {
		log.Fatal("ADMIN_API_KEY env var must be set for admin authentication")
	}

	db, err := initDB("data/forward.db")
	if err != nil {
		log.Fatalf("failed to init db: %v", err)
	}

	srv := &Server{db: db, adminKey: adminKey}

	r := gin.Default()

	docs.SwaggerInfo.Title = "PPC Forward Service API"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.BasePath = "/api/v1"
	docs.SwaggerInfo.Description = "Admin creates customers and forwards call info; customers fetch latest info per phone number."
	api := r.Group("/api/v1")

	admin := api.Group("/")
	admin.Use(srv.requireAdmin())
	admin.POST("/create-customer", srv.handleCreateCustomer)
	admin.POST("/forward-info", srv.handleUpsertForwardInfo)
	admin.PATCH("/customer/:id", srv.handleUpdateCustomer)
	admin.DELETE("/customer/:id", srv.handleDeleteCustomer)

	customer := api.Group("/")
	customer.Use(srv.requireCustomer())
	customer.GET("/forward-info", srv.handleGetForwardInfo)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	if err := r.Run(":" + port); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func initDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(1)

	schema := []string{
		`CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            api_key TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );`,
		`CREATE TABLE IF NOT EXISTS forward_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT NOT NULL UNIQUE,
            summary TEXT,
            interaction_id TEXT,
            start_time INTEGER,
            end_time INTEGER,
            duration INTEGER,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );`,
	}

	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			return nil, fmt.Errorf("apply schema: %w", err)
		}
	}

	return db, nil
}

// requireAdmin checks the shared admin API key in X-Admin-Key header.
func (s *Server) requireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("X-Admin-Key") != s.adminKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid admin key"})
			return
		}
		c.Next()
	}
}

// requireCustomer validates the customer API key and stores the customer id in context.
func (s *Server) requireCustomer() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-API-Key")
		if key == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing api key"})
			return
		}

		var id int64
		if err := s.db.QueryRow("SELECT id FROM customers WHERE api_key = ?", key).Scan(&id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid api key"})
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
			return
		}

		c.Set("customerID", id)
		c.Next()
	}
}

// createCustomerRequest holds admin input for customer provisioning.
type createCustomerRequest struct {
	Name string `json:"name" binding:"required"`
}

// handleCreateCustomer provisions an API key for a new customer.
// @Summary Create customer
// @Tags admin
// @Security AdminKey
// @Accept json
// @Produce json
// @Param body body createCustomerRequest true "Customer info"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /create-customer [post]
func (s *Server) handleCreateCustomer(c *gin.Context) {
	var req createCustomerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}

	apiKey := generateAPIKey()

	res, err := s.db.Exec("INSERT INTO customers (name, api_key) VALUES (?, ?)", req.Name, apiKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create customer"})
		return
	}

	id, _ := res.LastInsertId()
	c.JSON(http.StatusCreated, gin.H{"id": id, "name": req.Name, "api_key": apiKey})
}

// updateCustomerRequest allows admin to change name and/or rotate API key.
type updateCustomerRequest struct {
	Name              *string `json:"name"`
	APIKey            *string `json:"api_key"`
	RegenerateAPIKey  bool    `json:"regenerate_api_key"`
}

// handleUpdateCustomer lets admin rename a customer or rotate their API key.
// @Summary Update customer
// @Tags admin
// @Security AdminKey
// @Param id path int true "Customer ID"
// @Param body body updateCustomerRequest true "Fields to update"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /customer/{id} [patch]
func (s *Server) handleUpdateCustomer(c *gin.Context) {
	idParam := c.Param("id")
	var req updateCustomerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}

	var current struct {
		id     int64
		name   string
		apiKey string
	}
	if err := s.db.QueryRow("SELECT id, name, api_key FROM customers WHERE id = ?", idParam).Scan(&current.id, &current.name, &current.apiKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "customer not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
		return
	}

	newName := current.name
	newKey := current.apiKey

	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name cannot be empty"})
			return
		}
		newName = trimmed
	}

	if req.RegenerateAPIKey {
		newKey = generateAPIKey()
	} else if req.APIKey != nil {
		if strings.TrimSpace(*req.APIKey) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "api_key cannot be empty"})
			return
		}
		newKey = *req.APIKey
	}

	if newName == current.name && newKey == current.apiKey {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no changes supplied"})
		return
	}

	if _, err := s.db.Exec("UPDATE customers SET name = ?, api_key = ? WHERE id = ?", newName, newKey, current.id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"id": current.id, "name": newName, "api_key": newKey})
}

// handleDeleteCustomer removes a customer.
// @Summary Delete customer
// @Tags admin
// @Security AdminKey
// @Param id path int true "Customer ID"
// @Success 204 "deleted"
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /customer/{id} [delete]
func (s *Server) handleDeleteCustomer(c *gin.Context) {
	idParam := c.Param("id")
	res, err := s.db.Exec("DELETE FROM customers WHERE id = ?", idParam)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	count, _ := res.RowsAffected()
	if count == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "customer not found"})
		return
	}
	c.Status(http.StatusNoContent)
}

// forwardInfoRequest holds the payload sent by the admin.
type forwardInfoRequest struct {
	PhoneNumber   string `json:"phone_number" binding:"required"`
	Summary       string `json:"summary" binding:"required"`
	InteractionID string `json:"interaction_id" binding:"required"`
	StartTime     int64  `json:"start_time" binding:"required"`
	EndTime       int64  `json:"end_time" binding:"required"`
	Duration      int64  `json:"duration" binding:"required"`
}

// handleUpsertForwardInfo inserts or updates the latest info for a phone number.
// @Summary Upsert forward info
// @Tags admin
// @Security AdminKey
// @Accept json
// @Produce json
// @Param body body forwardInfoRequest true "Forward info"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /forward-info [post]
func (s *Server) handleUpsertForwardInfo(c *gin.Context) {
	var req forwardInfoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}

	normalized, err := normalizePhone(req.PhoneNumber)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err = s.db.Exec(`
        INSERT INTO forward_info (phone_number, summary, interaction_id, start_time, end_time, duration, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, strftime('%s','now'))
        ON CONFLICT(phone_number) DO UPDATE SET
            summary=excluded.summary,
            interaction_id=excluded.interaction_id,
            start_time=excluded.start_time,
            end_time=excluded.end_time,
            duration=excluded.duration,
            updated_at=strftime('%s','now');
    `, normalized, req.Summary, req.InteractionID, req.StartTime, req.EndTime, req.Duration)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to store forward info"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"phone_number": normalized, "status": "stored"})
}

// handleGetForwardInfo returns the latest info for a phone number.
// @Summary Get latest forward info by phone number
// @Tags customer
// @Security CustomerKey
// @Produce json
// @Param phone_number query string true "Phone number"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /forward-info [get]
func (s *Server) handleGetForwardInfo(c *gin.Context) {
	phone := c.Query("phone_number")
	if phone == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "phone_number is required"})
		return
	}

	normalized, err := normalizePhone(phone)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var info forwardInfoRequest
	row := s.db.QueryRow("SELECT phone_number, summary, interaction_id, start_time, end_time, duration FROM forward_info WHERE phone_number = ?", normalized)
	var phoneStored string
	if err := row.Scan(&phoneStored, &info.Summary, &info.InteractionID, &info.StartTime, &info.EndTime, &info.Duration); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "no info found for phone number"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"summary":        info.Summary,
		"interaction_id": info.InteractionID,
		"start_time":     info.StartTime,
		"end_time":       info.EndTime,
		"duration":       info.Duration,
	})
}

func normalizePhone(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("phone number cannot be empty")
	}

	cleaned := strings.Map(func(r rune) rune {
		if r == '+' || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, raw)

	for _, p := range phonePrefixes {
		if strings.HasPrefix(cleaned, p) {
			cleaned = strings.TrimPrefix(cleaned, p)
			break
		}
	}

	cleaned = strings.TrimPrefix(cleaned, "+")

	if len(cleaned) == 9 && cleaned[0] != '0' {
		cleaned = "0" + cleaned
	}

	if !strings.HasPrefix(cleaned, "0") {
		return "", fmt.Errorf("unsupported phone prefix")
	}

	if len(cleaned) < 9 {
		return "", fmt.Errorf("phone number too short after normalization")
	}

	return cleaned, nil
}

func generateAPIKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err == nil {
		return base64.RawURLEncoding.EncodeToString(b)
	}
	// Rare fallback if crypto/rand fails.
	return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
}
