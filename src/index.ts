// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {error, IRequest, json, Router, StatusError} from 'itty-router';
import {Auth, createAuth} from './auth';
import {Buffer} from 'node:buffer';
import {MAX_UPLOAD_LENGTH_BYTES, TUS_VERSION, X_SIGNAL_CHECKSUM_SHA256} from './uploadHandler';
import {toBase64} from './util';
import {parseUploadMetadata} from './parse';
import {DEFAULT_RETRY_PARAMS, retry, isR2RangedReadHeaderError, RetryBucket,} from './retry';

export {UploadHandler, BackupUploadHandler, AttachmentUploadHandler} from './uploadHandler';

const DO_CALL_TIMEOUT = 1000 * 60 * 30; // 20 minutes

export interface Env {
    SHARED_AUTH_SECRET: string;

    ATTACHMENT_BUCKET: R2Bucket;

    BACKUP_BUCKET: R2Bucket;

    ATTACHMENT_UPLOAD_HANDLER: DurableObjectNamespace;

    BACKUP_UPLOAD_HANDLER: DurableObjectNamespace;
}

const ATTACHMENT_PREFIX = 'attachments';
const BACKUP_PREFIX = 'backups';


// lazy init because it requires env but is expensive to create
let auth: Auth | undefined;

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
        withAuthenticatedUser,
        withAuthorizedKeyFromMetadata,
        uploadHandler)
    .patch(`/upload/${ATTACHMENT_PREFIX}/:id+`,
        withNamespace(ATTACHMENT_PREFIX),
        withAuthenticatedUser,
        withAuthorizedKeyFromPath,
        uploadHandler)
    .head(`/upload/${ATTACHMENT_PREFIX}/:id+`,
        withNamespace(ATTACHMENT_PREFIX),
        withAuthenticatedUser,
        withAuthorizedKeyFromPath,
        uploadHandler)

    // --- backup handler methods ---
    // GET/HEADs go straight to R2 and must include a subdir that is authenticated with a read permission
    // TUS operations go to a durable object and require authentication with a write permission

    // read the object :subdir/:id directly from R2, the request needs read permissions for :subdir
    .get(`/${BACKUP_PREFIX}/:subdir/:id+`,
        withNamespace(BACKUP_PREFIX),
        withAuthenticatedUser,
        withReadAuthorization,
        withSubdirAuthorizedKey,
        getHandler)
    // head the object :subdir/:id directly from R2, the request needs read permissions for :subdir
    .head(`/${BACKUP_PREFIX}/:subdir/:id+`,
        withNamespace(BACKUP_PREFIX),
        withAuthenticatedUser,
        withReadAuthorization,
        withSubdirAuthorizedKey,
        headHandler)
    // TUS protocol operations, dispatched to an UploadHandler durable object
    .post(`/upload/${BACKUP_PREFIX}`,
        withNamespace(BACKUP_PREFIX),
        withAuthenticatedUser,
        withWriteAuthorization,
        withAuthorizedKeyFromMetadata,
        uploadHandler)
    .patch(`/upload/${BACKUP_PREFIX}/:id+`,
        withNamespace(BACKUP_PREFIX),
        withAuthenticatedUser,
        withWriteAuthorization,
        withAuthorizedKeyFromPath,
        uploadHandler)
    .head(`/upload/${BACKUP_PREFIX}/:id+`,
        withNamespace(BACKUP_PREFIX),
        withAuthenticatedUser,
        withWriteAuthorization,
        withAuthorizedKeyFromPath,
        uploadHandler)

    .all('*', () => error(404));

export default {
    async fetch(
        request: Request,
        env: Env,
        ctx: ExecutionContext
    ): Promise<Response> {
        return router.fetch(request, env, ctx).catch(e => {
            console.log('error: ' + e.stack);
            if (e instanceof StatusError) {
                return error(e);
            }
            throw e;
        }).then(json);
    }
};


async function getHandler(request: IRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const requestId = request.key;

    const bucket: R2Bucket = request.namespace.bucket;
    if (bucket == null) {
        return error(404);
    }

    const cache = caches.default;
    const cacheKey = new Request(new URL(request.url.toString()), request);
    let response = await cache.match(cacheKey);
    if (response != null) {
        return response;
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
        response = new Response(object.body, {headers, status: 206});
        // We do not cache partial content responses (cloudflare does not allow it)
        // However, if we've previously cached the entire object and a ranged read
        // request comes in for the object, cloudflare will satisfy the partial
        // content request from the cache.
        // See https://developers.cloudflare.com/workers/runtime-apis/cache
        return response;
    } else {
        response = new Response(object.body, {headers});
        ctx.waitUntil(cache.put(cacheKey, response.clone()));
        return response;
    }
}

async function headHandler(request: IRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const requestId = request.key;

    const bucket: R2Bucket = request.namespace.bucket;
    if (bucket == null) {
        return error(404);
    }

    const cache = caches.default;
    const cacheKey = new Request(new URL(request.url.toString()), request);
    const response = await cache.match(cacheKey);
    if (response != null) {
        return response;
    }

    const head = await new RetryBucket(bucket, DEFAULT_RETRY_PARAMS).head(requestId);
    if (head == null) {
        return error(404);
    }
    const headers = objectHeaders(head);
    headers.set('Content-Length', head.size.toString());
    return new Response(null, {status: 200, headers: headers});
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
            'Tus-Max-Size': MAX_UPLOAD_LENGTH_BYTES.toString(),
            'Tus-Extension': 'creation,creation-defer-length,creation-with-upload,expiration'
        })
    });
}

// TUS protocol requests (POST/PATCH/HEAD) that get forwarded to a durable object
async function uploadHandler(request: IRequest, env: Env): Promise<Response> {
    const requestId: string = request.key;

    // The id of the DurableObject is derived from the authenticated upload id provided by the requester
    const durableObjNs: DurableObjectNamespace = request.namespace.doNamespace;
    if (durableObjNs == null) {
        return error(500, 'invalid bucket configuration');
    }

    return retry(async () => {
        const handler = durableObjNs.get(durableObjNs.idFromName(requestId));
        return await handler.fetch(request.url, {
            body: request.body,
            method: request.method,
            headers: request.headers,
            signal: AbortSignal.timeout(DO_CALL_TIMEOUT)
        });
    }, {params: DEFAULT_RETRY_PARAMS, shouldRetry: isRetryableDurableObjectError});
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
}

// Returns the durable object namespace and R2 bucket to use for operations against the provided path prefix
function selectNamespace(env: Env, prefix: string): Namespace | undefined {
    switch (prefix) {
        case ATTACHMENT_PREFIX:
            return {
                doNamespace: env.ATTACHMENT_UPLOAD_HANDLER,
                bucket: env.ATTACHMENT_BUCKET,
                name: ATTACHMENT_PREFIX
            };
        case BACKUP_PREFIX:
            return {
                doNamespace: env.BACKUP_UPLOAD_HANDLER,
                bucket: env.BACKUP_BUCKET,
                name: BACKUP_PREFIX
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
    state: 'error',
    error: Response
}

interface Credentials {
    state: 'success',
    user: string,
    password: string
}

function parseBasicAuth(auth: string): Credentials | ParseError {
    const prefix = 'Basic ';
    if (!auth.startsWith(prefix)) {
        return {state: 'error', error: error(400, 'auth should be Basic ')};
    }
    const cred = auth.slice(prefix.length);
    const decoded = Buffer.from(cred, 'base64').toString('utf8');

    const [username, ...rest] = decoded.split(':');
    const password = rest.join(':');
    if (!username || !password) {
        return {state: 'error', error: error(400, 'invalid auth format')};
    }
    return {state: 'success', user: username, password: password};
}


// Set request.user to the user from the basic auth credentials if the credential passes authentication
async function withAuthenticatedUser(request: IRequest, env: Env, _ctx: ExecutionContext): Promise<Response | undefined> {
    auth = auth || await createAuth(env.SHARED_AUTH_SECRET, 3600 * 24 * 7);
    const authHeader = request.headers.get('Authorization');
    if (!authHeader) {
        return error(401, 'missing credentials');
    }

    const parsed = parseBasicAuth(authHeader);
    if (parsed.state === 'error') {
        return parsed.error;
    }

    const valid = await auth.validateCredentials(parsed.user, parsed.password);
    if (!valid) {
        return error(401, 'invalid credentials');
    }
    request.user = parsed.user;
}


// Auth usernames are of the form [permission$]namespace/entity. withAuthenticatedUser ensures that the username is
// a valid credential. After that we must also ensure that the user is authorized to perform the requested action.
// - If the endpoint requires permission, the permission field must be extracted and checked
// - The namespace must match the path prefix, e.g. attachments or backups
// - For uploads, the entity must match the target of the upload operation (which may be specified via path or metadata)
// - For non-public reads, the entity must match the top-level parent directory of the read-target


// Extracts the permission specifier from the already authenticated request.user and if it is 'read', set request.user
// to the rest of the username
function withReadAuthorization(request: IRequest, env: Env, _ctx: ExecutionContext): Response | undefined {
    return withPermission('read', request, env);
}

// Extracts the permission specifier from the already authenticated request.user and if it is 'write', set request.user
// to the rest of the username
function withWriteAuthorization(request: IRequest, env: Env, _ctx: ExecutionContext): Response | undefined {
    return withPermission('write', request, env);
}

// Strips off the permission specifier and make sure it matches expectedPermission
function withPermission(expectedPermission: string, request: IRequest, _env: Env): Response | undefined {
    // the user should be set by a prior middleware (and should already have been authenticated)
    if (!request.user) {
        return error(500);
    }
    // strip off the permission and check it
    const splAt = request.user.indexOf('$');
    if (splAt === -1) {
        return error(401);
    }
    const permission = request.user.substring(0, splAt);
    if (permission !== expectedPermission) {
        return error(401);
    }

    // set the user as the remainder of the username
    request.user = request.user.substring(splAt + 1);
}

// Set request.key to :subdir/:id from the request path, if the authenticated user matches :subdir
function withSubdirAuthorizedKey(request: IRequest, env: Env, _ctx: ExecutionContext): Response | undefined {
    return setAuthorizedKey({
        keyExtractor: (request) => `${request.params.subdir}/${request.params.id}`,
        entityExtractor: (request) => request.params.subdir
    }, request, env);
}

// Set request.key to the name extracted from :id in the request path, if the authenticated user matches the name
function withAuthorizedKeyFromPath(request: IRequest, env: Env, _ctx: ExecutionContext): Response | undefined {
    return setAuthorizedKey({keyExtractor: (request) => `${request.params.id}`}, request, env);
}

// Set request.key to the name extracted from the uploadMetadata, if the authenticated user the name
function withAuthorizedKeyFromMetadata(request: IRequest, env: Env, _ctx: ExecutionContext): Response | undefined {
    return setAuthorizedKey({
        keyExtractor: (request) => parseUploadMetadata(request.headers).filename
    }, request, env);
}

export interface AuthOptions {
    // How to extract the key that will be attached to the request after a successful check
    keyExtractor: (request: IRequest) => string | undefined;
    // How to extract the expected contents of the username after the permission. If not
    // specified, defaults to the key
    entityExtractor?: (request: IRequest) => string | undefined;
}

// Set request.key to the request's target if the (already authenticated) username matches the expected username for
// that target
function setAuthorizedKey(authOptions: AuthOptions, request: IRequest, _env: Env): Response | undefined {
    // the user should be set by a prior middleware (and should already have been authenticated)
    if (!request.user) {
        return error(500);
    }

    // the namespace should have been set based on the request path by a prior middleware
    if (!request.namespace) {
        return error(404);
    }

    // the key within the namespace that this request will operate on
    const key = authOptions.keyExtractor(request);
    if (!key) {
        return error(401);
    }

    // the entity within the namespace that should match the provided username
    const expectedEntity = (authOptions.entityExtractor || authOptions.keyExtractor)(request);
    if (!expectedEntity) {
        return error(401);
    }

    // the username must match the expected entity that grants permission to the key
    if (request.user !== `${request.namespace.name}/${expectedEntity}`) {
        return error(401);
    }
    request.key = key;
}


// Set request.key without any authentication (public access)
function withUnauthenticatedKeyFromId(request: IRequest, _env: Env, _ctx: ExecutionContext): Response | undefined {
    request.key = request.params.id;
    return;
}
