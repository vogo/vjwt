jwt auth utility

design:

- only contains `sub`,`exp`,`uid` in jwt claims
    - `sub` is the subject of the token, which is the user id
    - `exp` is the expiration time of the token, which is a UNIX timestamp in the future, in seconds, as integer
    - `uid` is the user id, which is deprecated, use `sub` instead
- signing default using HS256

