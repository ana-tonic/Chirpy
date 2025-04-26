# Chirpy

Chirpy is a Twitter-clone application written in Go that allows users to post short messages (chirps), manage their accounts, and interact with other users.

## Features

- User registration and authentication
- Posting chirps (tweets)
- Viewing chirps with sorting capabilities
- User account management
- Chirpy Red premium membership support
- Metrics and monitoring

## Technical Requirements

- Go 1.21 or newer
- PostgreSQL database
- Docker (optional)

## Project Setup

1. Clone the repository:
```bash
git clone https://github.com/ana-tonic/Chirpy.git
cd Chirpy
```

2. Create a `.env` file with the following variables:
```env
DB_URL=postgres://username:password@localhost:5432/chirpy?sslmode=disable
TOKEN_SECRET=your-secret-key
PLATFORM=dev
POLKA_KEY=your-polka-key
```

3. Install dependencies:
```bash
go mod download
```

4. Run the application:
```bash
go run main.go
```

## API Endpoints

### Users
- `POST /api/users` - Register a new user
- `PUT /api/users` - Update user account
- `POST /api/login` - User login
- `POST /api/refresh` - Refresh JWT token
- `POST /api/revoke` - Revoke refresh token

### Chirps
- `POST /api/chirps` - Create a new chirp
- `GET /api/chirps` - View all chirps
- `GET /api/chirps/{id}` - View a specific chirp
- `DELETE /api/chirps/{id}` - Delete a chirp

### Admin
- `GET /api/healthz` - Health check
- `GET /admin/metrics` - View metrics
- `POST /admin/reset` - Reset metrics

### Webhook
- `POST /api/polka/webhooks` - Webhook for Chirpy Red subscriptions

## Security

- JWT authentication implemented
- Passwords are hashed using bcrypt
- XSS attack protection implemented
- All user inputs are validated

## Development

For development, we recommend using Docker to set up the PostgreSQL database:

```bash
docker run --name chirpy-db -e POSTGRES_PASSWORD=password -e POSTGRES_DB=chirpy -p 5432:5432 -d postgres
```

## License

MIT 