# WordPress REST API Key Authentication Plugin

Make authenticated requests to the WP API using API keys.

This plugin allows administrators to issue (and revoke) API keys and shared secrets to users on your site which can be used to make authenticated requests to WP API endpoints. Authentication is accomplished using hash-based message authentication codes ([HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code)) with the [SHA256 hash algorithm](https://en.wikipedia.org/wiki/SHA-2).

This plugin provides a simpler alternative OAuth1 for non-browser based auth flows (e.g. cron scripts).

## How to Sign your WP API Requests

1. Generate API keys & shared secrets for any users you would like to authenticate as by visiting the User Edit screen in the WP Admin.
2. Create a canonical request string for your request
3. Generate a request signature by signing the canonical request string with your shared secret using (HMAC-SHA256)[].
4. Add the `X-API-TIMESTAMP`, `X-API-KEY` and `X-API-SIGNATURE` headers to your request.

### Canonical Request String Format

The canonical request string combines the following request components in to a newline separated text string:

- API key
- Request timestamp (numeric UNIX timestamp, e.g. 1444758767)
- Request METHOD (e.g. 'GET' or 'POST')
- Request URI (including query string, e.g. '/wp-json/wp/v2/users/me' or '/wp-json/wp/v2/posts?per_page=10')
- Request body (URL-encoded string of key sorted form data)

## Example Requests

The following sample requests using these credentials:

- Key: GSKHQMBGH2Ns
- Shared Secret: u4SCmkK9sctXfjDyJwfXh3dt65OpJ67xcv89kSIOUeKbNSEt

Example GET request issued at 10/13/2015 @ 5:52pm (UTC):

```bash
# Raw Request
GET /wp-json/wp/v2/posts?per_page=5 HTTP/1.1

# Canonical Request
GSKHQMBGH2Ns
1444758767
GET
/wp-json/wp/v2/posts?per_page=5


# Signed Request
GET /wp-json/wp/v2/users/2 HTTP/1.1
X-API-TIMESTAMP: 1444758767
X-API-KEY: GSKHQMBGH2Ns
X-API-SIGNATURE: a8584be47384ae279ed51d305bf6a96fd11da0ec55e0bbdddfeb6c586113f5cf
```

Example POST request at 10/13/2015 @ 6:21pm (UTC):

```bash
# Raw Request
POST /wp-json/wp/v2/posts HTTP/1.1

# Canonical Request
GSKHQMBGH2Ns
1444760517
POST
/wp-json/wp/v2/posts
content=This+post+was+created+using+WP+API+with+the+%3Ca+href%3D%22https%3A%2F%2Fgithub.com%2Fmgburns%2Fkey-auth%22%3EKey+Auth+plugin%3C%2Fa%3E&title=New+Post+from+Key+Auth

# Signed Request
POST /wp-json/wp/v2/posts HTTP/1.1
X-API-TIMESTAMP: 1444760517
X-API-KEY: GSKHQMBGH2Ns
X-API-SIGNATURE: 0df18ad42d05fe6f4c23ac9468ce660391b0e80dc813bd9e716b9e03215f6a09
```

## Installation

Drop this directory in and activate it. You need to be using pretty permalinks
to use the plugin, as it uses custom rewrite rules to power the API.

## Issue Tracking

All tickets for the project are being tracked on [Github](https://github.com/mgburns/Key-Auth).
