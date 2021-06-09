# JWT Auth Go

This is an example implementation of JWT auth in Go. This should NOT be used in production; there's no database and the users don't have passwords. This should only be used as a reference when building your own authentication system.

## Routes

| Route          | Data Required                             | Returns                                                      |
| -------------- | ----------------------------------------- | ------------------------------------------------------------ |
| POST `/signup` | Body: `{ "username": "" }`                | `accessToken` (exp in 15 seconds), `refreshToken`, and `uid` |
| POST `/login`  | Body: `{ "username": "" }`                | `accessToken` (exp in 15 seconds), and `refreshToken`        |
| GET `/me`      | Header: `Authorization: Bearer tokenHere` | Your username                                                |
| PUT `/refresh` | Body: `{ "token": "" }`                   | new `accessToken` (exp in 15 seconds)                        |
| POST `/logout` | Body: `{ "token": "" }`                   | Deletes token, sends back status                             |

License: MIT
