## JWT Generator

In order to use Push API /v1/registration with custom_user_id field, the value of custom_user_id needs to be encrypted as a Java Web Token.

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

Base64 encoded string (to use SHARE_SECRET mentioned above a convert from HEX to Base64 is needed)
