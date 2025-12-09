# PPC Forward Service

Gin-based service that lets an admin provision customers and upsert call forward info, while customers fetch the latest info per phone number. Data is stored in SQLite.

## Requirements
- Go 1.25+
- SQLite (embedded via `modernc.org/sqlite`, no external binary needed)

## Configuration
Set environment variables (see `.env` for an example):

- `ADMIN_API_KEY` (required) — shared secret for admin endpoints.
- `PORT` (optional) — HTTP port, defaults to `8080`.

Load the defaults:

```bash
source .env
```

## Run
```bash
go run .
# or
PORT=9090 ADMIN_API_KEY=supersecret go run .
```

The server listens on `:PORT` and serves API under `/api/v1`. Swagger UI is at `/swagger/index.html`.

## Phone number normalization
- Accepts national (`0722123456`) or international with `+`, `00`, or bare country code (e.g. `+40722123456`, `0040722123456`, `40722123456`).
- Supports many country codes out of the box: `+40`, `+972`, `+1`, `+44`, `+49`, `+33`, `+39`, `+34`, `+30`, `+31`, `+32`, `+351`–`+359`, `+81`, `+82`, `+86`, `+852`, `+853`, `+90`–`+98`, and more.
- Strips the international prefix and normalizes to a consistent digit-only form (adds a leading `0` for 9‑digit national numbers), so the same number is treated identically across the supported formats.

## Admin endpoints (header: `X-Admin-Key: <ADMIN_API_KEY>`, base path `/api/v1`)

### Create customer
```bash
curl -X POST http://localhost:8080/api/v1/create-customer \
  -H "X-Admin-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme"}'
```
Customer names are unique. A request with an existing name returns `409 Conflict`.

### Update customer (rename / rotate key)
```bash
curl -X PUT http://localhost:8080/api/v1/customer/1 \
  -H "X-Admin-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Europe","regenerate_api_key":true}'
```

### Delete customer
```bash
curl -X DELETE http://localhost:8080/api/v1/customer/1 \
  -H "X-Admin-Key: $ADMIN_API_KEY"
```

### List customers
```bash
curl http://localhost:8080/api/v1/customers \
  -H "X-Admin-Key: $ADMIN_API_KEY"
```

### Upsert forward info
```bash
curl -X POST http://localhost:8080/api/v1/forward-info \
  -H "X-Admin-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "customer_api_key": "<customer_api_key>",
    "phone_number": "+40722123456",
    "summary": "Call about pricing",
    "interaction_id": "int-123",
    "start_time": 1733670000,
    "end_time": 1733670035,
    "duration": 35
  }'
```
Forward info is stored per customer; different customers can store different data for the same phone number, distinguished by `customer_api_key`.

## Customer endpoint (header: `X-API-Key: <customer_api_key>`, base path `/api/v1`)

### Get latest forward info
```bash
curl "http://localhost:8080/api/v1/forward-info?phone_number=+40722123456" \
  -H "X-API-Key: <customer_api_key>"
```

Example response:
```json
{
  "summary": "Call about pricing",
  "interaction_id": "int-123",
  "start_time": 1733670000,
  "end_time": 1733670035,
  "duration": 35
}
```

## Swagger
- UI: `http://localhost:8080/swagger/index.html`
- Re-generate after handler/comment changes:
```bash
$(go env GOPATH)/bin/swag init --parseDependency --parseInternal --output docs
```

## Database
- File: `data/forward.db` (auto-created).
- Tables: `customers`, `forward_info` (one row per normalized phone number, upsert on conflict).
