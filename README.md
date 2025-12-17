# PPC Forward Service for Genesys Integration

Dedicated service for PPC (must win in Romania) that enables getting information from low-code straight into genesys.

## Flow
- Conversation is received from PPC's genesys cloud
- Conversation Handled by Wonderful AI agent
- Low code tool summerizes the call, publishes to the service **Before** Forwarding to genesys
- Genesys webhook triggerred, fetched the information published by the low code
- Call summary and other relevant fields from the conversation is shown in genesys 🎉

## Single-slot queue semantics
- The service now behaves like a queue with capacity **1 per customer**.
- An admin `POST /forward-info` waits until the customer slot is free (no timeout), then queues its payload and returns immediately with `"status":"queued"`.
- Once queued, the item must be consumed within **10 seconds**; otherwise it expires and is dropped.
- Only one unconsumed entry can exist at a time for a customer. If another admin call arrives while one is pending, it waits (potentially forever) until that pending item is consumed or expires, then proceeds.
- The customer `GET /forward-info` always returns the **latest unconsumed** item, consumes it (removing it from the queue), and ignores the `phone_number` query param.
- Concurrency edge case: if two admin calls land simultaneously on an empty queue, one enqueues and the other waits; if the first item is consumed within 10s the waiter proceeds immediately, otherwise it proceeds after the first item expires at 10s.

## Deployment
- Deployed on aws ec2 machine called ppc-forward
- Served on https://ppc.forwardapi.wonderful.ai/api/v1

connecting via ssh (authorization required)
```
ssh  ubuntu@ec2-54-93-35-83.eu-central-1.compute.amazonaws.com
```



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
# or with env from .env
./run.sh
# background mode (persists after SSH): logs to server.log by default
./run.sh --background
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
  -d '{"name":"Acme","default_country_code":"40"}'
```
Customer names are unique. A request with an existing name returns `409 Conflict`.
`default_country_code` is the numeric country code (e.g., `"40"` for Romania, `"972"` for Israel, `"1"` for US/Canada) used to infer a full international prefix when numbers arrive without one.
Optional `default_extra_data` (JSON object) sets fallback key/value pairs that will be merged into GET responses whenever no `extra_data` is present for a record or when an error response is returned.

### Update customer (rename / rotate key)
```bash
curl -X PUT http://localhost:8080/api/v1/customer/1 \
  -H "X-Admin-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Europe","regenerate_api_key":true,"default_extra_data":{"brand":"Acme","locale":"en-US"}}'
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
    "customer_name": "Acme",
    "phone_number": "0722123456",
    "summary": "Call about pricing",
    "interaction_id": "int-123",
    "start_time": 1733670000,
    "end_time": 1733670035,
    "duration": 35,
    "extra_data": {"agent": "Maria", "topic": "pricing", "is_vip": true}
  }'
```
If the phone number does not include an international prefix, the customer's `default_country_code` is automatically prepended (e.g., `0722...` becomes `+40 722...` for Romania) before normalization. Forward info is stored per customer; different customers can store different data for the same phone number, distinguished by `customer_name` in the admin upsert request.

`extra_data` is optional and must be a JSON object. Its key/value pairs are stored as-is and later merged into the customer-facing GET response at the top level (flat structure). Keys that collide with built-in fields (`summary`, `interaction_id`, `start_time`, `end_time`, `duration`, `error`) are ignored.
Queue behavior for this endpoint:
- If no entry is pending, the payload is queued and the HTTP response returns immediately with `{"status":"queued","expires_in_seconds":10,...}`.
- If the queued item is consumed within 10s, customers get it and the slot clears; if not, it auto-expires after 10s and the slot frees.
- If another item is still pending when you POST, your request waits until that item is consumed or expires, then queues your payload; there is no POST timeout for waiting on the slot.

## Customer endpoint (header: `X-API-Key: <customer_api_key>`, base path `/api/v1`)

### Get latest forward info
```bash
curl "http://localhost:8080/api/v1/forward-info" \
  -H "X-API-Key: <customer_api_key>"
```

Example response:
```json
{
  "summary": "Call about pricing",
  "interaction_id": "int-123",
  "start_time": 1733670000,
  "end_time": 1733670035,
  "duration": 35,
  "agent": "Maria",
  "topic": "pricing",
  "is_vip": true,
  "error": ""
}
```
Notes:
- The `phone_number` query parameter is ignored; the endpoint always returns the latest unconsumed item for that customer.
- Each successful GET consumes the queued item, clearing the slot for the next admin POST.
- If the queue is empty, the response keeps the same shape with base fields empty/zero, includes `"error": "phone_number_not_found"`, and merges `default_extra_data` (if any) at the top level.

## Swagger
- UI: `http://localhost:8080/swagger/index.html`
- Re-generate after handler/comment changes:
```bash
$(go env GOPATH)/bin/swag init --parseDependency --parseInternal --output docs
```

## Database
- File: `data/forward.db` (auto-created).
- Tables: `customers`, `forward_info` (legacy; current queue behavior keeps only in-memory pending items per customer).
