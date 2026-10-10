# babel

Passwordless authentication service built with Go and Echo.

Users request a login link by email and sign in by visiting the link.

## Layout

```
cmd/babel/main.go          entrypoint and wiring
internal/config            environment configuration
internal/store             storage interface and SQLite implementation
internal/auth              tokens and JWT
internal/mailer            mail sending interface and SMTP implementation
internal/service           business logic
internal/handler           HTTP handlers and routing
internal/middleware        auth and rate limit middleware
internal/web               templates and rendering
```

## Run

```
go run ./cmd/babel
```

The server listens on `127.0.0.1:8080` by default and reads `.env` when present.

## Deploy

Deployments are manual:

```
make deploy
```

## Storage

The current implementation uses SQLite. The storage layer is behind an interface so a Postgres implementation can be added without changing handlers or services.
