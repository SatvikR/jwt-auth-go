# JWT Auth Go

This is an example implementation of JWT auth in Go. This should NOT be used in production. This should only be used as a reference when building your own authentication system.

This implements JWT auth using two token types: Access and Refresh. The refresh tokens are stored as http only cookies, and the access tokens should be stored in memory on a frontend client.

## Config

Setup postgresql database

```sql
CREATE DATABASE somedbname;
```

Connect to the database and run:

```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

Create a `.env` file with six variables

```
ACCESS_TOKEN_SECRET=
REFRESH_TOKEN_SECRET=
DB_ADDR=
DB_USER=
DB_PASSWORD=
DB_NAME=
```

## Routes

| Method | Route      | Data Required                              | Returns                               |
| ------ | ---------- | ------------------------------------------ | ------------------------------------- |
| POST   | `/signup`  | Body: `{ "username": "", "password": "" }` | `accessToken` (exp in 15 seconds)     |
| POST   | `/login`   | Body: `{ "username": "", "password": "" }` | `accessToken` (exp in 15 seconds)     |
| GET    | `/me`      | Header: `Authorization: Bearer tokenHere`  | Your username                         |
| PUT    | `/refresh` |                                            | New `accessToken` (exp in 15 seconds) |
| DELETE | `/logout`  |                                            | Deletes token, sends back status      |

License: MIT
