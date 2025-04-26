-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    $1,
    $2
)
RETURNING *;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: UpdateUser :exec
UPDATE users
SET email = $2, hashed_password = $3
WHERE id = $1;

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = $1;

-- name: SetIsChirpyRed :exec
UPDATE users
SET is_chirpy_red = $2
WHERE id = $1;

-- name: GetChirpsByAuthorID :many
SELECT * FROM chirps
WHERE user_id = $1;
