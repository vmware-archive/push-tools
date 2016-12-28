## JWT Generator

In order to use Push API /v1/registration with custom_user_id field, the value of custom_user_id needs to be encoded as a Java Web Token.

```bash
./jwt-gen generatehex SHARE_SECRET custom_user_id
```
The SHARE_SECRET can be found on Push dashboard -> Configuration -> Application info.

This tool generates the JWT token by

**JWT Header**
```
{
  "alg": "HS256"
}
```
**JWT Payload**
```
{
  "custom_user_id": YOUR_CUSTOM_USER_ID
}
```

**Secret**

Hex encoded SHARE_SECRET
