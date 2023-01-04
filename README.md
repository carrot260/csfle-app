## Prerequisites

- Requires OpenSky API (https://github.com/openskynetwork/opensky-api)
- Set enviroment variables for AWS access key (ACCESS_KEY), Secret (SECRET_KEY), Customer Master Key ARN (CMK), Master Key Region (KEY_REGION) and Atlas Connection string (ATLAS_CONNECTION_STRING).

## Additional Notes

## Important

Field that is used for findOne query using encrypted client must use `AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic` algorithm for encryption