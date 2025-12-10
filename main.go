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
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
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

type apiError string

const (
	errorPhoneNumberNotFound apiError = "phone_number_not_found"
)

var (
	phoneCountryCodes = []string{
		"1", "20", "27", "30", "31", "32", "33", "34", "39", "40", "44", "49",
		"60", "61", "62", "63", "64", "65", "66",
		"7", "81", "82", "86", "90", "91", "92", "93", "94", "95", "98",
		"211", "212", "213", "216", "218", "254", "255", "256", "257", "258", "260", "261", "262", "263", "264", "265", "266", "267", "268", "269",
		"290", "299",
		"351", "352", "353", "354", "355", "356", "357", "358", "359",
		"372", "373", "374", "375", "376", "377", "378", "380", "381", "382", "385", "386", "387", "389",
		"420", "421", "423",
		"501", "502", "503", "504", "505", "506", "507", "508", "509",
		"590", "591", "592", "593", "594", "595", "596", "597", "598", "599",
		"670", "672", "673", "674", "675", "676", "677", "678", "679",
		"680", "681", "682", "683", "685", "686", "687", "688", "689",
		"690", "691", "692", "850", "852", "853", "855", "856", "880", "886", "960", "961", "962", "963", "964", "965", "966", "967", "968", "970", "971", "972", "973", "974", "975", "976", "977", "992", "993", "994", "995", "996", "998",
	}
	phonePrefixes = buildPhonePrefixes(phoneCountryCodes)
)

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
	admin.PUT("/customer/:id", srv.handleUpdateCustomer)
	admin.DELETE("/customer/:id", srv.handleDeleteCustomer)
	admin.GET("/customers", srv.handleListCustomers)

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
		`PRAGMA foreign_keys = ON;`,
		`CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            api_key TEXT NOT NULL UNIQUE,
            default_country_code TEXT NOT NULL DEFAULT '40',
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );`,
		`DROP TABLE IF EXISTS forward_info;`,
		`CREATE TABLE forward_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            phone_number TEXT NOT NULL,
            summary TEXT,
            interaction_id TEXT,
            start_time INTEGER,
            end_time INTEGER,
            duration INTEGER,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(customer_id, phone_number),
            FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
        );`,
		`CREATE INDEX IF NOT EXISTS idx_forward_info_customer ON forward_info(customer_id);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_name ON customers(name);`,
		// For existing databases: add column if it doesn't yet exist.
		`ALTER TABLE customers ADD COLUMN default_country_code TEXT NOT NULL DEFAULT '40';`,
	}

	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") && strings.Contains(err.Error(), "customers.name") {
				return nil, fmt.Errorf("apply schema (customer name uniqueness): %w; resolve duplicate names before retrying", err)
			}
			if strings.Contains(err.Error(), "duplicate column name") && strings.Contains(err.Error(), "default_country_code") {
				continue
			}
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
		var defaultCC string
		if err := s.db.QueryRow("SELECT id, default_country_code FROM customers WHERE api_key = ?", key).Scan(&id, &defaultCC); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid api key"})
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
			return
		}

		c.Set("customerID", id)
		c.Set("customerDefaultCC", defaultCC)
		c.Next()
	}
}

// createCustomerRequest holds admin input for customer provisioning.
type createCustomerRequest struct {
	Name               string `json:"name" binding:"required"`
	DefaultCountryCode string `json:"default_country_code" binding:"required"`
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
// @Failure 409 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /create-customer [post]
func (s *Server) handleCreateCustomer(c *gin.Context) {
	var req createCustomerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name cannot be empty"})
		return
	}

	cc := strings.TrimSpace(req.DefaultCountryCode)
	if err := validateCountryCode(cc); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var existingID int64
	err := s.db.QueryRow("SELECT id FROM customers WHERE name = ?", name).Scan(&existingID)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "customer name already exists", "id": existingID})
		return
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not verify name uniqueness"})
		return
	}

	apiKey := generateAPIKey()

	res, err := s.db.Exec("INSERT INTO customers (name, api_key, default_country_code) VALUES (?, ?, ?)", name, apiKey, cc)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") && strings.Contains(err.Error(), "customers.name") {
			c.JSON(http.StatusConflict, gin.H{"error": "customer name already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create customer"})
		return
	}

	id, _ := res.LastInsertId()
	c.JSON(http.StatusCreated, gin.H{"id": id, "name": name, "api_key": apiKey})
}

// updateCustomerRequest allows admin to change name and/or rotate API key.
type updateCustomerRequest struct {
	Name               *string `json:"name"`
	APIKey             *string `json:"api_key"`
	DefaultCountryCode *string `json:"default_country_code"`
	RegenerateAPIKey   bool    `json:"regenerate_api_key"`
}

// handleUpdateCustomer lets admin rename a customer or rotate their API key.
// @Summary Update customer
// @Tags admin
// @Security AdminKey
// @Param id path int true "Customer ID"
// @Param body body updateCustomerRequest true "Fields to update"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /customer/{id} [put]
func (s *Server) handleUpdateCustomer(c *gin.Context) {
	idParam := c.Param("id")
	var req updateCustomerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}

	var current struct {
		id                 int64
		name               string
		apiKey             string
		defaultCountryCode string
	}
	if err := s.db.QueryRow("SELECT id, name, api_key, default_country_code FROM customers WHERE id = ?", idParam).Scan(&current.id, &current.name, &current.apiKey, &current.defaultCountryCode); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "customer not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
		return
	}

	newName := current.name
	newKey := current.apiKey
	newCC := current.defaultCountryCode

	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name cannot be empty"})
			return
		}
		newName = trimmed
	}

	if newName != current.name {
		var otherID int64
		err := s.db.QueryRow("SELECT id FROM customers WHERE name = ?", newName).Scan(&otherID)
		if err == nil && otherID != current.id {
			c.JSON(http.StatusConflict, gin.H{"error": "customer name already exists", "id": otherID})
			return
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not verify name uniqueness"})
			return
		}
	}

	if req.DefaultCountryCode != nil {
		if err := validateCountryCode(strings.TrimSpace(*req.DefaultCountryCode)); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		newCC = strings.TrimSpace(*req.DefaultCountryCode)
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

	if newName == current.name && newKey == current.apiKey && newCC == current.defaultCountryCode {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no changes supplied"})
		return
	}

	if _, err := s.db.Exec("UPDATE customers SET name = ?, api_key = ?, default_country_code = ? WHERE id = ?", newName, newKey, newCC, current.id); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") && strings.Contains(err.Error(), "customers.name") {
			c.JSON(http.StatusConflict, gin.H{"error": "customer name already exists"})
			return
		}
		if strings.Contains(err.Error(), "UNIQUE") && strings.Contains(err.Error(), "customers.api_key") {
			c.JSON(http.StatusConflict, gin.H{"error": "api_key already exists"})
			return
		}
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
	tx, err := s.db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}

	if _, err := tx.Exec("DELETE FROM forward_info WHERE customer_id = ?", idParam); err != nil {
		_ = tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}

	res, err := tx.Exec("DELETE FROM customers WHERE id = ?", idParam)
	if err != nil {
		_ = tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	count, _ := res.RowsAffected()
	if count == 0 {
		_ = tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "customer not found"})
		return
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}

	c.Status(http.StatusNoContent)
}

// customerRecord is returned in list responses.
type customerRecord struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	APIKey             string `json:"api_key"`
	DefaultCountryCode string `json:"default_country_code"`
	CreatedAt          string `json:"created_at"`
}

// handleListCustomers returns all customers.
// @Summary List customers
// @Tags admin
// @Security AdminKey
// @Produce json
// @Success 200 {array} customerRecord
// @Failure 500 {object} map[string]string
// @Router /customers [get]
func (s *Server) handleListCustomers(c *gin.Context) {
	rows, err := s.db.Query("SELECT id, name, api_key, default_country_code, created_at FROM customers ORDER BY id ASC")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not list customers"})
		return
	}
	defer rows.Close()

	var customers []customerRecord
	for rows.Next() {
		var rec customerRecord
		if err := rows.Scan(&rec.ID, &rec.Name, &rec.APIKey, &rec.DefaultCountryCode, &rec.CreatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read customers"})
			return
		}
		customers = append(customers, rec)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read customers"})
		return
	}

	c.JSON(http.StatusOK, customers)
}

// forwardInfoRequest holds the payload sent by the admin.
type forwardInfoRequest struct {
	CustomerName  string `json:"customer_name" binding:"required"`
	PhoneNumber   string `json:"phone_number" binding:"required"`
	Summary       string `json:"summary" binding:"required"`
	InteractionID string `json:"interaction_id" binding:"required"`
	StartTime     int64  `json:"start_time" binding:"required"`
	EndTime       int64  `json:"end_time" binding:"required"`
	Duration      int64  `json:"duration" binding:"required"`
}

type forwardInfoResponse struct {
	Summary       string `json:"summary"`
	InteractionID string `json:"interaction_id"`
	StartTime     int64  `json:"start_time"`
	EndTime       int64  `json:"end_time"`
	Duration      int64  `json:"duration"`
	Error         string `json:"error"`
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

	customerName := strings.TrimSpace(req.CustomerName)
	if customerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "customer_name cannot be empty"})
		return
	}

	var customerID int64
	var defaultCC string
	if err := s.db.QueryRow("SELECT id, default_country_code FROM customers WHERE name = ?", customerName).Scan(&customerID, &defaultCC); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "customer not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "customer lookup failed"})
		return
	}

	normalized, err := normalizePhone(req.PhoneNumber, defaultCC, true)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err = s.db.Exec(`
        INSERT INTO forward_info (customer_id, phone_number, summary, interaction_id, start_time, end_time, duration, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%s','now'))
        ON CONFLICT(customer_id, phone_number) DO UPDATE SET
            summary=excluded.summary,
            interaction_id=excluded.interaction_id,
            start_time=excluded.start_time,
            end_time=excluded.end_time,
            duration=excluded.duration,
            updated_at=strftime('%s','now');
    `, customerID, normalized, req.Summary, req.InteractionID, req.StartTime, req.EndTime, req.Duration)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to store forward info"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"phone_number": normalized, "customer_id": customerID, "customer_name": customerName, "status": "stored"})
}

// handleGetForwardInfo returns the latest info for a phone number.
// @Summary Get latest forward info by phone number
// @Tags customer
// @Security CustomerKey
// @Produce json
// @Param phone_number query string true "Phone number"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /forward-info [get]
func (s *Server) handleGetForwardInfo(c *gin.Context) {
	phone := c.Query("phone_number")
	if phone == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "phone_number is required"})
		return
	}

	defaultCC, _ := c.Get("customerDefaultCC")
	ccStr, _ := defaultCC.(string)

	normalized, err := normalizePhone(phone, ccStr, true)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	customerID, ok := c.Get("customerID")
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "customer context missing"})
		return
	}

	candidates := []string{normalized}
	if alt, err := normalizePhoneWithoutDefault(phone); err == nil && alt != normalized {
		candidates = append(candidates, alt)
	}

	var info forwardInfoResponse
	var phoneStored string
	found := false
	for _, cand := range candidates {
		row := s.db.QueryRow("SELECT phone_number, summary, interaction_id, start_time, end_time, duration FROM forward_info WHERE customer_id = ? AND phone_number = ?", customerID, cand)
		if err := row.Scan(&phoneStored, &info.Summary, &info.InteractionID, &info.StartTime, &info.EndTime, &info.Duration); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
			return
		}
		found = true
		normalized = cand
		break
	}

	if !found {
		c.JSON(http.StatusOK, forwardInfoResponse{
			Error: string(errorPhoneNumberNotFound),
		})
		return
	}

	info.Error = ""
	c.JSON(http.StatusOK, info)
}

func normalizePhone(raw string, defaultCountryCode string, prependDefault bool) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("phone number cannot be empty")
	}

	cleaned := strings.Map(func(r rune) rune {
		if r == '+' || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, raw)

	if cleaned == "" {
		return "", fmt.Errorf("phone number cannot be empty")
	}

	defaultCountryCode = strings.TrimSpace(defaultCountryCode)
	if defaultCountryCode == "" {
		defaultCountryCode = "40"
	}
	if err := validateCountryCode(defaultCountryCode); err != nil {
		return "", err
	}

	// If no explicit international prefix, optionally prepend default country code.
	if prependDefault && !strings.HasPrefix(cleaned, "+") && !strings.HasPrefix(cleaned, "00") {
		cleaned = "+" + defaultCountryCode + cleaned
	}

	if strings.HasPrefix(cleaned, "00") {
		cleaned = "+" + strings.TrimPrefix(cleaned, "00")
	}

	localPrefixes := append([]string{"+" + defaultCountryCode, "00" + defaultCountryCode, defaultCountryCode}, phonePrefixes...)
	sort.Slice(localPrefixes, func(i, j int) bool { return len(localPrefixes[i]) > len(localPrefixes[j]) })

	prefixMatched := false
	for _, p := range localPrefixes {
		if strings.HasPrefix(cleaned, p) {
			cleaned = strings.TrimPrefix(cleaned, p)
			prefixMatched = true
			break
		}
	}

	cleaned = strings.TrimPrefix(cleaned, "+")

	if len(cleaned) == 0 {
		return "", fmt.Errorf("phone number too short after removing prefix")
	}

	if len(cleaned) == 9 && cleaned[0] != '0' {
		cleaned = "0" + cleaned
	}

	if len(cleaned) < 7 {
		return "", fmt.Errorf("phone number too short after normalization")
	}

	if !prefixMatched && !strings.HasPrefix(cleaned, "0") {
		return "", fmt.Errorf("unsupported phone prefix")
	}

	return cleaned, nil
}

func buildPhonePrefixes(codes []string) []string {
	var prefixes []string
	for _, code := range codes {
		prefixes = append(prefixes, "+"+code, "00"+code, code)
	}
	sort.Slice(prefixes, func(i, j int) bool { return len(prefixes[i]) > len(prefixes[j]) })
	return prefixes
}

func validateCountryCode(code string) error {
	if code == "" {
		return fmt.Errorf("default_country_code cannot be empty")
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return fmt.Errorf("default_country_code must contain digits only")
		}
	}
	if len(code) < 1 || len(code) > 4 {
		return fmt.Errorf("default_country_code must be 1 to 4 digits")
	}
	return nil
}

// normalizePhoneWithoutDefault leaves the number as-is (no automatic country prepend) but still strips known prefixes.
func normalizePhoneWithoutDefault(raw string) (string, error) {
	return normalizePhone(raw, "", false)
}

func generateAPIKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err == nil {
		return base64.RawURLEncoding.EncodeToString(b)
	}
	// Rare fallback if crypto/rand fails.
	return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
}
