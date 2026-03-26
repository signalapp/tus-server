// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {error, IRequest, json, Router, StatusError} from 'itty-router';
import {Buffer} from 'node:buffer';
import {jwtVerify, errors as joseErrors} from 'jose';
import {
    TUS_VERSION,
    X_SIGNAL_CHECKSUM_SHA256,
    X_SIGNAL_MAX_UPLOAD_LENGTH
} from './uploadHandler';
import {toBase64} from './util';
import {parseUploadMetadata} from './parse';
import {DEFAULT_RETRY_PARAMS, retry, isR2RangedReadHeaderError, RetryBucket,} from './retry';

export {UploadHandler, BackupUploadHandler, AttachmentUploadHandler} from './uploadHandler';

const DO_CALL_TIMEOUT = 1000 * 60 * 30; // 20 minutes
const MAX_TOKEN_AGE = 3600 * 24 * 7; // 7 days


export interface Env {
    SHARED_AUTH_SECRET: string;

    ATTACHMENT_BUCKET: R2Bucket;

    BACKUP_BUCKET: R2Bucket;

    ATTACHMENT_UPLOAD_HANDLER: DurableObjectNamespace;

    BACKUP_UPLOAD_HANDLER: DurableObjectNamespace;
}

const ATTACHMENT_PREFIX = 'attachments';
const BACKUP_PREFIX = 'backups';


const router = Router();
router
    // Describes what TUS features we support
    .options('/upload/:bucket', optionsHandler)

    // --- attachment handler methods ---
    // GET/HEADs go straight to R2 and are publicly accessible
    // TUS operations go to a durable object and require authentication

    // read the object :id directly from R2
    .get(`/${ATTACHMENT_PREFIX}/:id+`,
        withNamespace(ATTACHMENT_PREFIX),
        withUnauthenticatedKeyFromId,
        getHandler)
    // head the object :id directly from R2
    .head(`/${ATTACHMENT_PREFIX}/:id+`,
        withNamespace(ATTACHMENT_PREFIX),
        withUnauthenticatedKeyFromId,
        headHandler)
    // TUS protocol operations, dispatched to an UploadHandler durable object
    .post(`/upload/${ATTACHMENT_PREFIX}`,
        withNamespace(ATTACHMENT_PREFIX),
        withAuthenticatedClaims,
        withAuthorizedKeyFromMetadata,
        withAuthorizedUploadLength,
        uploadHandler)
    .patch(`/upload/${ATTACHMENT_PREFIX}/:id+`,
        withNamespace(ATTACHMENT_PREFIX),
        withAuthenticatedClaims,
        withAuthorizedKeyFromPath,
        withAuthorizedUploadLength,
        uploadHandler)
    .head(`/upload/${ATTACHMENT_PREFIX}/:id+`,
        withNamespace(ATTACHMENT_PREFIX),
        withAuthenticatedClaims,
        withAuthorizedKeyFromPath,
        withAuthorizedUploadLength,
        uploadHandler)

    // --- backup handler methods ---
    // GET/HEADs go straight to R2 and must include a subdir that is authenticated with a read permission
    // TUS operations go to a durable object and require authentication with a write permission

    // read the object :subdir/:id directly from R2, the request needs read permissions for :subdir
    .get(`/${BACKUP_PREFIX}/:subdir/:id+`,
        withNamespace(BACKUP_PREFIX),
        withAuthenticatedClaims,
        checkReadAuthorization,
        withSubdirAuthorizedKey,
        getHandler)
    // head the object :subdir/:id directly from R2, the request needs read permissions for :subdir
    .head(`/${BACKUP_PREFIX}/:subdir/:id+`,
        withNamespace(BACKUP_PREFIX),
        withAuthenticatedClaims,
        checkReadAuthorization,
        withSubdirAuthorizedKey,
        headHandler)
    // TUS protocol operations, dispatched to an UploadHandler durable object
    .post(`/upload/${BACKUP_PREFIX}`,
        withNamespace(BACKUP_PREFIX),
        withAuthenticatedClaims,
        checkWriteAuthorization,
        withAuthorizedKeyFromMetadata,
        withAuthorizedUploadLength,
        uploadHandler)
    .patch(`/upload/${BACKUP_PREFIX}/:id+`,
        withNamespace(BACKUP_PREFIX),
        withAuthenticatedClaims,
        checkWriteAuthorization,
        withAuthorizedKeyFromPath,
        withAuthorizedUploadLength,
        uploadHandler)
    .head(`/upload/${BACKUP_PREFIX}/:id+`,
        withNamespace(BACKUP_PREFIX),
        withAuthenticatedClaims,
        checkWriteAuthorization,
        withAuthorizedKeyFromPath,
        withAuthorizedUploadLength,
        uploadHandler)

    .all('*', () => error(404));

export default {
    async fetch(
        request: Request,
        env: Env,
        ctx: ExecutionContext
    ): Promise<Response> {
        return router.fetch(request, env, ctx).catch(e => {
            console.log(`error processing ${request.method}:${request.url}: ${e.stack}`);
            if (e instanceof StatusError) {
                return error(e);
            }
            throw e;
        }).then(json);
    }
};


async function getHandler(request: IRequest, _env: Env, ctx: ExecutionContext): Promise<Response> {
    const requestId = request.key;

    const bucket: R2Bucket = request.namespace.bucket;
    if (bucket == null) {
        return error(404);
    }

    const {cacheKey, cachedResponse} = await checkCache(request);
    if (cachedResponse) {
        return cachedResponse;
    }

    let object;
    try {
        object = await new RetryBucket(bucket, DEFAULT_RETRY_PARAMS).get(requestId, {
            range: request.headers
        });
    } catch (e) {
        if (isR2RangedReadHeaderError(e)) {
            console.error(`Request for ${requestId} had unsatisfiable range ${request.headers.get('range')} : ${e}`);
            return error(416);
        }
        throw e;
    }
    if (object == null) {
        return error(404);
    }
    const headers = objectHeaders(object);
    if (object.range != null && request.headers.has('range')) {
        headers.set('content-range', rangeHeader(object.size, object.range));
        const response = new Response(object.body, {headers, status: 206});
        // We do not cache partial content responses (cloudflare does not allow it)
        // However, if we've previously cached the entire object and a ranged read
        // request comes in for the object, cloudflare will satisfy the partial
        // content request from the cache.
        // See https://developers.cloudflare.com/workers/runtime-apis/cache
        return response;
    } else {
        const response = new Response(object.body, {headers});
        if (cacheKey) {
            ctx.waitUntil(caches.default.put(cacheKey, response.clone()));
        }
        return response;
    }
}

async function headHandler(request: IRequest, _env: Env, _ctx: ExecutionContext): Promise<Response> {
    const requestId = request.key;

    const bucket: R2Bucket = request.namespace.bucket;
    if (bucket == null) {
        return error(404);
    }

    const {cachedResponse} = await checkCache(request);
    if (cachedResponse) {
        return cachedResponse;
    }

    const head = await new RetryBucket(bucket, DEFAULT_RETRY_PARAMS).head(requestId);
    if (head == null) {
        return error(404);
    }
    const headers = objectHeaders(head);
    headers.set('Content-Length', head.size.toString());
    return new Response(null, {status: 200, headers: headers});
}

async function checkCache(request: IRequest): Promise<{
    cacheKey: Request | undefined;
    cachedResponse: Response | undefined
}> {
    const cacheKey = request.namespace.useCache && new Request(new URL(request.url.toString()), request);
    if (!cacheKey) {
        return {cacheKey, cachedResponse: undefined};
    }
    return {
        cacheKey: cacheKey,
        cachedResponse: await caches.default.match(cacheKey, {
            // Lets us return HEAD responses from cached GET responses.
            ignoreMethod: true
        })
    };
}

function objectHeaders(object: R2Object): Headers {
    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set('etag', object.httpEtag);

    // the sha256 checksum was provided to R2 in the upload
    if (object.checksums.sha256 != null) {
        headers.set(X_SIGNAL_CHECKSUM_SHA256, toBase64(object.checksums.sha256));
    }

    // it was a multipart upload, so we were forced to write a sha256 checksum as a custom header
    if (object.customMetadata?.[X_SIGNAL_CHECKSUM_SHA256] != null) {
        headers.set(X_SIGNAL_CHECKSUM_SHA256, object.customMetadata[X_SIGNAL_CHECKSUM_SHA256]);
    }

    // RFC-9110 HTTP-date compliant
    headers.set('Last-Modified', object.uploaded.toUTCString());

    return headers;
}

function rangeHeader(objLen: number, r2Range: R2Range): string {
    let startIndexInclusive = 0;
    let endIndexInclusive = objLen - 1;
    if ('offset' in r2Range && r2Range.offset != null) {
        startIndexInclusive = r2Range.offset;
    }
    if ('length' in r2Range && r2Range.length != null) {
        endIndexInclusive = startIndexInclusive + r2Range.length - 1;
    }
    if ('suffix' in r2Range) {
        startIndexInclusive = objLen - r2Range.suffix;
    }
    return `bytes ${startIndexInclusive}-${endIndexInclusive}/${objLen}`;
}


async function optionsHandler(_request: IRequest, _env: Env): Promise<Response> {
    return new Response(null, {
        status: 204,
        headers: new Headers({
            'Tus-Resumable': TUS_VERSION,
            'Tus-Version': TUS_VERSION,
            'Tus-Extension': 'creation,creation-defer-length,creation-with-upload,expiration'
        })
    });
}

// TUS protocol requests (POST/PATCH/HEAD) that get forwarded to a durable object
async function uploadHandler(request: IRequest, _env: Env): Promise<Response> {
    const requestId: string = request.key;

    // The id of the DurableObject is derived from the authenticated upload id provided by the requester
    const durableObjNs: DurableObjectNamespace = request.namespace.doNamespace;
    if (durableObjNs == null) {
        return error(500, 'invalid bucket configuration');
    }

    const maxUploadLength = request.maxUploadLength;
    if (maxUploadLength == null) {
        return error(500, 'expected maximum upload length not found');
    }

    const headers = new Headers(request.headers);

    // Let the durable-object know what our authenticated max upload length is. Replace the header if the
    // user tried to set it themselves
    headers.set(X_SIGNAL_MAX_UPLOAD_LENGTH, maxUploadLength.toString());

    return retry(async () => {
        const handler = durableObjNs.get(durableObjNs.idFromName(requestId));
        return await handler.fetch(request.url, {
            body: request.body,
            method: request.method,
            headers: headers,
            signal: AbortSignal.timeout(DO_CALL_TIMEOUT)
        });
    }, {
        params: DEFAULT_RETRY_PARAMS,
        // Only retry requests without bodies. If the request has a body, the stream is consumed by the first request
        shouldRetry: (err) => request.body == null && isRetryableDurableObjectError(err)
    });
}

// Check if the error has the retryable flag set. This generally indicates a transient cloudflare system error
// See https://developers.cloudflare.com/durable-objects/best-practices/error-handling/
function isRetryableDurableObjectError(err: unknown): boolean {
    if (err != null && err instanceof Object && Object.prototype.hasOwnProperty.call(err, 'retryable')) {
        return (err as { retryable: boolean }).retryable;
    }
    return false;
}

interface Namespace {
    doNamespace: DurableObjectNamespace,
    bucket: R2Bucket
    name: 'attachments' | 'backups'
    useCache: boolean
}

// Returns the durable object namespace and R2 bucket to use for operations against the provided path prefix
function selectNamespace(env: Env, prefix: string): Namespace | undefined {
    switch (prefix) {
        case ATTACHMENT_PREFIX:
            return {
                doNamespace: env.ATTACHMENT_UPLOAD_HANDLER,
                bucket: env.ATTACHMENT_BUCKET,
                name: ATTACHMENT_PREFIX,
                useCache: true
            };
        case BACKUP_PREFIX:
            return {
                doNamespace: env.BACKUP_UPLOAD_HANDLER,
                bucket: env.BACKUP_BUCKET,
                name: BACKUP_PREFIX,
                useCache: false
            };
        default:
            return undefined;
    }
}

// Set request.namespace indicating the durable object / R2 bucket requests should be routed to
function withNamespace(bucket: string): (request: IRequest, env: Env, ctx: ExecutionContext) => Response | undefined {
    return (request, env, _ctx) => {
        request.namespace = selectNamespace(env, bucket);
        if (request.namespace == null) {
            return error(404);
        }
    };
}

interface ParseError {
    type: 'error',
    error: Response
}

interface Token {
    type: 'bearer',
    token: string,
}

function parseAuthHeader(auth: string): Token | ParseError {
    const bearer = 'Bearer ';
    if (auth.startsWith(bearer)) {
        return {type: 'bearer', token: auth.slice(bearer.length)};
    } else {
        return {type: 'error', error: error(400, 'invalid auth format')};
    }
}

// Set request.authenticatedClaims if the credential passes authentication
async function withAuthenticatedClaims(request: IRequest, env: Env, _ctx: ExecutionContext): Promise<Response | undefined> {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader) {
        return error(401, 'missing credentials');
    }

    // the namespace should have been set by a prior middleware and should match the audience in the credential
    const namespace: Namespace = request.namespace;
    if (namespace == null) {
        return error(401);
    }

    const parsed = parseAuthHeader(authHeader);
    if (parsed.type === 'error') {
        return parsed.error;
    }
    const authenticatedClaims = await authenticateToken(namespace, env.SHARED_AUTH_SECRET, parsed);

    if (authenticatedClaims === null) {
        return error(401, 'invalid credentials');
    }

    request.authenticatedClaims = authenticatedClaims;
}

interface AuthenticatedClaims {
    audience: string;
    subject: string;
    scope?: 'read' | 'write';
    maxUploadLength?: number;
}


async function authenticateToken(namespace: Namespace, secretString: string, jwtToken: Token): Promise<AuthenticatedClaims | null> {
    const secret = new Uint8Array(Buffer.from(secretString, 'base64'));
    try {
        const {payload} = await jwtVerify(jwtToken.token, secret, {
            algorithms: ['HS256'],
            audience: namespace.name,
            maxTokenAge: MAX_TOKEN_AGE
        });
        const sub = payload.sub;
        const maxLen = typeof payload.maxLen === 'number' ? payload.maxLen : undefined;
        if (!sub) {
            return null;
        }
        const scope = payload.scope as string | undefined;
        if (scope !== undefined && scope !== 'read' && scope !== 'write') {
            return null;
        }
        return {
            audience: namespace.name,
            subject: sub,
            scope: scope,
            maxUploadLength: maxLen
        };
    } catch (e) {
        if (e instanceof joseErrors.JOSEError) {
            return null;
        }
        throw e;
    }
}


// withAuthenticatedClaims ensures that the request has a valid credential signed by the appropriate authority.
// After that we must also ensure that the credential is authorized to perform the requested action.
// - If the endpoint requires permission, the permission field must be extracted and checked
// - The namespace must match the path prefix, e.g. attachments or backups
// - For uploads, the entity must match the target of the upload operation (which may be specified via path or metadata)
// - For non-public reads, the entity must match the top-level parent directory of the read-target

// Verify that the permission specifier in the already authenticated claims is set to 'read'
function checkReadAuthorization(request: IRequest, _env: Env, _ctx: ExecutionContext): Response | undefined {
    if (authenticatedClaims(request).scope !== 'read') {
        return error(401);
    }
}

// Verify that the permission specifier in the already authenticated claims is set to 'write'
function checkWriteAuthorization(request: IRequest, _env: Env, _ctx: ExecutionContext): Response | undefined {
    if (authenticatedClaims(request).scope !== 'write') {
        return error(401);
    }
}

// Set request.key to :subdir/:id from the request path, if the authenticated subject matches :subdir
function withSubdirAuthorizedKey(request: IRequest, _env: Env, _ctx: ExecutionContext): Response | undefined {
    const claims = authenticatedClaims(request);
    if (claims.subject !== request.params.subdir) {
        return error(401);
    }
    request.key = `${request.params.subdir}/${request.params.id}`;
}

// Set request.key to the name extracted from :id in the request path, if the authenticated subject matches the name
function withAuthorizedKeyFromPath(request: IRequest, _env: Env, _ctx: ExecutionContext): Response | undefined {
    const claims = authenticatedClaims(request);
    if (claims.subject !== request.params.id) {
        return error(401);
    }
    request.key = request.params.id;
}

// Set request.key to the name extracted from the uploadMetadata, if the authenticated subject matches the name
function withAuthorizedKeyFromMetadata(request: IRequest, _env: Env, _ctx: ExecutionContext): Response | undefined {
    const claims = authenticatedClaims(request);
    const key = parseUploadMetadata(request.headers).filename;
    if (claims.subject !== key) {
        return error(401);
    }
    request.key = key;
}

// Set request.maxUploadLength to the upload length extracted from the claims
function withAuthorizedUploadLength(request: IRequest, _env: Env, _ctx: ExecutionContext): Response | undefined {
    const claims = authenticatedClaims(request);
    if (claims.maxUploadLength == null) {
        return error(401);
    }
    request.maxUploadLength = claims.maxUploadLength;
}

// Set request.key without any authentication (public access)
function withUnauthenticatedKeyFromId(request: IRequest, _env: Env, _ctx: ExecutionContext): Response | undefined {
    request.key = request.params.id;
    return;
}

// Return the previously authenticated claims from a request or throw an error
function authenticatedClaims(request: IRequest): AuthenticatedClaims {
    // the claims should have been set by a prior middleware
    const claims: AuthenticatedClaims = request.authenticatedClaims;
    if (!claims) {
        throw new StatusError(500, 'expected claims were not found');
    }
    return claims;
}
