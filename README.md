# @authrim/server

Official Authrim Server SDK for OAuth 2.0 / OpenID Connect resource server implementation.

This SDK is part of the [Authrim](https://github.com/authrim) identity platform, providing token validation, DPoP support, and framework middleware for server-side applications.

## Features

- **JWT Access Token Validation** - Signature verification and claims validation (RFC 7519)
- **JWKS Management** - Automatic key fetching, caching, and rotation
- **DPoP Support** - RFC 9449 compliant proof validation
- **Token Introspection** - RFC 7662 support
- **Token Revocation** - RFC 7009 support
- **Back-Channel Logout** - OIDC Back-Channel Logout 1.0 support
- **Framework Middleware** - Express, Fastify, Hono, Koa, NestJS
- **SCIM 2.0** - User and Group provisioning (RFC 7643/7644)
- **Verifiable Credentials** - OpenID4VCI and OpenID4VP support

## Installation

```bash
npm install @authrim/server
# or
pnpm add @authrim/server
# or
yarn add @authrim/server
```

## Quick Start

```typescript
import { AuthrimServer } from '@authrim/server';

const server = new AuthrimServer({
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
});

await server.init();

// Validate a token
const result = await server.validateToken(accessToken);
if (result.data) {
  console.log('User:', result.data.claims.sub);
  console.log('Token Type:', result.data.tokenType); // 'Bearer' or 'DPoP'
} else {
  console.error('Error:', result.error.code, result.error.message);
}
```

## Runtime Support

This SDK uses Web Standard APIs (fetch, crypto.subtle) and runs on:

- Node.js 18+
- Bun
- Deno
- Cloudflare Workers
- Vercel Edge Functions

## Configuration

```typescript
const server = new AuthrimServer({
  // Required
  issuer: 'https://auth.example.com',        // Expected token issuer
  audience: 'https://api.example.com',       // Expected audience (string or string[])

  // JWKS (one of these is required)
  jwksUri: 'https://auth.example.com/.well-known/jwks.json',  // Explicit JWKS URI
  // or omit to use OpenID Discovery (issuer + /.well-known/openid-configuration)

  // Optional: Token operations
  introspectionEndpoint: 'https://auth.example.com/oauth/introspect',
  revocationEndpoint: 'https://auth.example.com/oauth/revoke',
  clientCredentials: {
    clientId: 'resource-server',
    clientSecret: 'secret',
  },

  // Optional: Timing
  clockToleranceSeconds: 60,      // Clock skew tolerance (default: 60)
  jwksRefreshIntervalMs: 3600000, // JWKS cache TTL (default: 1 hour)

  // Optional: Security
  requireHttps: true,             // Require HTTPS for all endpoints (default: true)

  // Optional: Custom providers (for testing/customization)
  http: customHttpProvider,
  crypto: customCryptoProvider,
  clock: customClockProvider,
});
```

## Framework Middleware

### Express

```typescript
import express from 'express';
import { AuthrimServer } from '@authrim/server';
import { authrimMiddleware } from '@authrim/server/adapters/express';

const app = express();
const server = new AuthrimServer({
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
});

await server.init();

app.use('/api', authrimMiddleware(server));

app.get('/api/protected', (req, res) => {
  res.json({ user: req.auth.claims.sub });
});
```

### Fastify

```typescript
import Fastify from 'fastify';
import { AuthrimServer } from '@authrim/server';
import { authrimPreHandler } from '@authrim/server/adapters/fastify';

const fastify = Fastify();
const server = new AuthrimServer({
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
});

await server.init();

fastify.addHook('preHandler', authrimPreHandler(server));

fastify.get('/api/protected', async (request) => {
  return { user: request.auth.claims.sub };
});
```

### Hono

```typescript
import { Hono } from 'hono';
import { AuthrimServer } from '@authrim/server';
import { authrimMiddleware, getAuth } from '@authrim/server/adapters/hono';

const app = new Hono();
const server = new AuthrimServer({
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
});

await server.init();

app.use('/api/*', authrimMiddleware(server));

app.get('/api/protected', (c) => {
  const auth = getAuth(c);
  return c.json({ user: auth?.claims.sub });
});
```

### Koa

```typescript
import Koa from 'koa';
import { AuthrimServer } from '@authrim/server';
import { authrimMiddleware } from '@authrim/server/adapters/koa';

const app = new Koa();
const server = new AuthrimServer({
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
});

await server.init();

app.use(authrimMiddleware(server));

app.use((ctx) => {
  ctx.body = { user: ctx.state.auth?.claims.sub };
});
```

### NestJS

```typescript
import { Controller, Get, UseGuards } from '@nestjs/common';
import { HttpException } from '@nestjs/common';
import { AuthrimServer } from '@authrim/server';
import { createAuthrimGuard, Auth } from '@authrim/server/adapters/nestjs';
import type { ValidatedToken } from '@authrim/server';

const server = new AuthrimServer({
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
});

const AuthrimGuard = createAuthrimGuard(server, HttpException);

@Controller('api')
export class AppController {
  @Get('protected')
  @UseGuards(AuthrimGuard)
  getProtected(@Auth() auth: ValidatedToken) {
    return { user: auth.claims.sub };
  }
}
```

## DPoP Support

DPoP (Demonstrating Proof of Possession) binds access tokens to a specific client key pair.

```typescript
import { AuthrimServer, DPoPValidator } from '@authrim/server';

const server = new AuthrimServer({
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
});

await server.init();

// 1. Validate the access token
const tokenResult = await server.validateToken(accessToken);
if (tokenResult.error) {
  // Handle error
}

// 2. Check if token is DPoP-bound
if (tokenResult.data.tokenType === 'DPoP') {
  // 3. Validate DPoP proof
  const dpopResult = await server.validateDPoP(dpopProof, {
    method: 'GET',
    uri: 'https://api.example.com/resource',
    accessToken: accessToken,
    expectedThumbprint: tokenResult.data.claims.cnf?.jkt,
  });

  if (!dpopResult.valid) {
    // DPoP proof invalid
    return { error: dpopResult.errorCode };
  }
}
```

### DPoP with Nonce

```typescript
const dpopResult = await server.validateDPoP(dpopProof, {
  method: 'POST',
  uri: 'https://api.example.com/token',
  expectedNonce: serverProvidedNonce,
});

if (dpopResult.errorCode === 'dpop_nonce_required') {
  // Client should retry with the nonce
}
```

## Token Introspection

```typescript
const server = new AuthrimServer({
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
  introspectionEndpoint: 'https://auth.example.com/oauth/introspect',
  clientCredentials: {
    clientId: 'resource-server',
    clientSecret: 'secret',
  },
});

await server.init();

const result = await server.introspect(token);
if (result.active) {
  console.log('Token is active');
  console.log('Subject:', result.sub);
  console.log('Scope:', result.scope);
}
```

## Token Revocation

```typescript
const server = new AuthrimServer({
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
  revocationEndpoint: 'https://auth.example.com/oauth/revoke',
  clientCredentials: {
    clientId: 'resource-server',
    clientSecret: 'secret',
  },
});

await server.init();

// Revoke access token
await server.revoke(accessToken);

// Revoke refresh token
await server.revoke(refreshToken, 'refresh_token');
```

## Back-Channel Logout

Handle logout tokens sent by the Authorization Server via back-channel.

```typescript
import { BackChannelLogoutValidator } from '@authrim/server';

const validator = new BackChannelLogoutValidator();

// Endpoint to receive logout tokens
app.post('/backchannel-logout', async (req, res) => {
  const logoutToken = req.body.logout_token;

  // 1. Validate logout token claims (synchronous)
  const result = validator.validate(logoutToken, {
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com',
    clockToleranceSeconds: 60,
    now: Math.floor(Date.now() / 1000),
  });

  if (!result.valid) {
    return res.status(400).json({ error: result.error.code });
  }

  // 2. Verify signature using JWKS (application responsibility)
  // 3. Check jti for replay (application responsibility)

  // 4. Terminate sessions
  const { sub, sid } = result.claims;
  if (sid) {
    await terminateSession(sid);
  } else if (sub) {
    await terminateAllUserSessions(sub);
  }

  res.status(200).end();
});
```

## SCIM 2.0 Provisioning

```typescript
import { ScimClient } from '@authrim/server';

const scim = new ScimClient({
  baseUrl: 'https://api.example.com/scim/v2',
  accessToken: token,
});

// Create user
const user = await scim.createUser({
  userName: 'john@example.com',
  name: { givenName: 'John', familyName: 'Doe' },
  emails: [{ value: 'john@example.com', primary: true }],
  active: true,
});

// Get user
const fetchedUser = await scim.getUser(user.id);

// Update user
await scim.updateUser(user.id, {
  ...user,
  active: false,
});

// List users with filter
const users = await scim.listUsers({
  filter: 'userName eq "john@example.com"',
  startIndex: 1,
  count: 10,
});

// Delete user
await scim.deleteUser(user.id);

// Group operations
const group = await scim.createGroup({
  displayName: 'Admins',
  members: [{ value: user.id }],
});
```

## Error Handling

All validation methods return a result object with `data` or `error`:

```typescript
const result = await server.validateToken(token);

if (result.error) {
  // Handle specific error codes
  switch (result.error.code) {
    case 'token_expired':
      // Token has expired
      break;
    case 'invalid_issuer':
      // Wrong issuer
      break;
    case 'invalid_audience':
      // Wrong audience
      break;
    case 'signature_invalid':
      // Signature verification failed
      break;
    case 'jwks_key_not_found':
      // Key not found in JWKS
      break;
    default:
      // Other error
  }

  // HTTP status for response
  const httpStatus = result.error.httpStatus; // 401, 503, etc.
}
```

### Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `token_malformed` | Token is not a valid JWT | 401 |
| `token_expired` | Token has expired | 401 |
| `invalid_issuer` | Issuer doesn't match expected | 401 |
| `invalid_audience` | Audience doesn't match expected | 401 |
| `signature_invalid` | Signature verification failed | 401 |
| `jwks_key_not_found` | Signing key not in JWKS | 401 |
| `jwks_fetch_failed` | Failed to fetch JWKS | 503 |
| `dpop_proof_missing` | DPoP proof required but missing | 401 |
| `dpop_proof_invalid` | DPoP proof validation failed | 401 |
| `dpop_nonce_required` | Server nonce required | 401 |

## Provider Injection

All dependencies are injectable for testing and customization:

```typescript
import { AuthrimServer } from '@authrim/server';
import {
  fetchHttpProvider,
  webCryptoProvider,
  systemClock,
  memoryCache
} from '@authrim/server/providers';

const server = new AuthrimServer({
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',

  // Custom providers
  http: fetchHttpProvider(),
  crypto: webCryptoProvider(),
  clock: systemClock(),
  jwksCache: memoryCache({ ttlMs: 3600_000 }),
});
```

### Testing with Mocks

```typescript
import { vi } from 'vitest';

const mockClock = {
  nowMs: () => 1700000000000,
  nowSeconds: () => 1700000000,
};

const mockCrypto = {
  verifySignature: vi.fn().mockResolvedValue(true),
  importJwk: vi.fn().mockResolvedValue({} as CryptoKey),
  sha256: vi.fn().mockResolvedValue(new Uint8Array(32)),
  calculateThumbprint: vi.fn().mockResolvedValue('thumbprint'),
};

const server = new AuthrimServer({
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
  jwksUri: 'https://auth.example.com/.well-known/jwks.json',
  crypto: mockCrypto,
  clock: mockClock,
});
```

## Security Considerations

### HTTPS Enforcement

By default, all endpoints must use HTTPS. Disable only for development:

```typescript
const server = new AuthrimServer({
  issuer: 'http://localhost:8080',  // Will throw error
  requireHttps: false,               // Allow HTTP (development only!)
});
```

### Timing-Safe Comparisons

This SDK uses constant-time string comparisons for security-sensitive values:
- JWT issuer and audience validation
- DPoP thumbprint binding verification
- Back-channel logout subject and session ID validation

### JTI Replay Protection

For DPoP proofs and logout tokens, `jti` (JWT ID) uniqueness checking is the **application's responsibility**. Implement a cache with TTL:

```typescript
const jtiCache = new Map<string, number>();
const JTI_LIFETIME_SECONDS = 120;

function checkJtiUniqueness(jti: string): boolean {
  const now = Math.floor(Date.now() / 1000);

  // Clean expired entries
  for (const [key, exp] of jtiCache) {
    if (exp < now) jtiCache.delete(key);
  }

  if (jtiCache.has(jti)) {
    return false; // Replay detected
  }

  jtiCache.set(jti, now + JTI_LIFETIME_SECONDS);
  return true;
}
```

### JWKS Security

- Cross-origin redirects are blocked by default
- Cache-Control headers are respected (max 24 hours)
- Single-flight pattern prevents thundering herd

## API Reference

### AuthrimServer

| Method | Description |
|--------|-------------|
| `init()` | Initialize the server (fetch JWKS if needed) |
| `validateToken(token)` | Validate a JWT access token |
| `validateDPoP(proof, options)` | Validate a DPoP proof |
| `introspect(token)` | Introspect a token (RFC 7662) |
| `revoke(token, tokenTypeHint?)` | Revoke a token (RFC 7009) |
| `invalidateJwksCache()` | Force JWKS cache refresh |

### BackChannelLogoutValidator

| Method | Description |
|--------|-------------|
| `validate(token, options)` | Validate logout token claims |

### ScimClient

| Method | Description |
|--------|-------------|
| `createUser(user)` | Create a new user |
| `getUser(id)` | Get user by ID |
| `updateUser(id, user)` | Replace user |
| `patchUser(id, operations)` | Patch user |
| `deleteUser(id)` | Delete user |
| `listUsers(options?)` | List/search users |
| `createGroup(group)` | Create a new group |
| `getGroup(id)` | Get group by ID |
| `updateGroup(id, group)` | Replace group |
| `patchGroup(id, operations)` | Patch group |
| `deleteGroup(id)` | Delete group |
| `listGroups(options?)` | List/search groups |

## RFC Compliance

| Specification | Status |
|---------------|--------|
| RFC 7519 - JWT | Implemented |
| RFC 7517 - JWK | Implemented |
| RFC 7638 - JWK Thumbprint | Implemented |
| RFC 7662 - Token Introspection | Implemented |
| RFC 7009 - Token Revocation | Implemented |
| RFC 9449 - DPoP | Implemented |
| RFC 7643/7644 - SCIM 2.0 | Implemented |
| OIDC Core 1.0 | Implemented |
| OIDC Back-Channel Logout 1.0 | Implemented |

## Authrim SDK Family

This SDK is part of the Authrim identity platform:

| Package | Description |
|---------|-------------|
| `@authrim/core` | Client-side SDK for OAuth 2.0 / OIDC flows |
| `@authrim/server` | Server-side SDK for token validation (this package) |

## jose Dependency

This SDK uses `jose` for type definitions. Cryptographic operations use the native Web Crypto API. Other Authrim language SDKs may use different libraries (e.g., Nimbus for Java, go-jose for Go, Microsoft.IdentityModel for .NET) as long as the same verification steps are followed.

## License

Apache-2.0

Copyright (c) Authrim
