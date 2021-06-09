# JWT Auth Go

This is an example implementation of JWT auth in Go. This should NOT be used in production; there's no database and the users don't have passwords. This should only be used as a reference when building your own authentication system.

This implements JWT auth using two token types: Access and Refresh. The refresh tokens are stored as http only cookies, and the access tokens should be stored in memory on a frontend client.

## Routes

| Method | Route      | Data Required                             | Returns                               |
| ------ | ---------- | ----------------------------------------- | ------------------------------------- |
| POST   | `/signup`  | Body: `{ "username": "" }`                | `accessToken` (exp in 15 seconds)     |
| POST   | `/login`   | Body: `{ "username": "" }`                | `accessToken` (exp in 15 seconds)     |
| GET    | `/me`      | Header: `Authorization: Bearer tokenHere` | Your username                         |
| PUT    | `/refresh` |                                           | New `accessToken` (exp in 15 seconds) |
| DELETE | `/logout`  |                                           | Deletes token, sends back status      |

License: MIT
