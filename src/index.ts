// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {error, IRequest, json, Router} from 'itty-router';
import {Auth, createAuth} from './auth';
import {Buffer} from 'node:buffer';
import {MAX_UPLOAD_LENGTH_BYTES, TUS_VERSION, X_SIGNAL_CHECKSUM_SHA256} from './uploadHandler';
import {toBase64} from './util';
import {parseUploadMetadata} from './parse';

export {UploadHandler} from './uploadHandler';

const DO_CALL_TIMEOUT = 1000 * 60 * 30; // 20 minutes

export interface Env {
    BUCKET: R2Bucket;

    SHARED_AUTH_SECRET: string;

    UPLOAD_HANDLER: DurableObjectNamespace;

    PATH_PREFIX: string;
}


// lazy init because it requires env but is expensive to create
let auth: Auth | undefined;

const router = Router();
router
    // read the object :id directly from R2
    .get('/:bucket/:id', getHandler)

    // TUS protocol operation, dispatched to an UploadHandler durable object
    .post('/upload/:bucket', withAuthenticatedKeyFromMetadata, uploadHandler)

    // TUS protocol operation, dispatched to an UploadHandler durable object
    .patch('/upload/:bucket/:id', withAuthenticatedKey, uploadHandler)

    // TUS protocol operation, dispatched to an UploadHandler durable object
    .head('/upload/:bucket/:id', withAuthenticatedKey, uploadHandler)

    // Describes what TUS features we support
    .options('/upload/:bucket', optionsHandler)

    .all('*', () => error(404));

export default {
    async fetch(
        request: Request,
        env: Env,
        _ctx: ExecutionContext
    ): Promise<Response> {
        return await router.handle(request, env).catch(e => {
            console.log('error: ' + e.stack);
            return error(e);
        }).then(json);
    }
};


async function getHandler(request: IRequest, env: Env): Promise<Response> {
    const requestId = request.params.id;
    if (request.params.bucket !== env.PATH_PREFIX) {
        return error(404);
    }

    const object = await env.BUCKET.get(requestId);

    if (object === null) {
        return error(404);
    }

    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set('etag', object.httpEtag);

    // the sha256 checksum was provided to R2 in the upload
    if (object.checksums.sha256 != null) {
        headers.set(X_SIGNAL_CHECKSUM_SHA256, toBase64(object.checksums.sha256));
    }

    // it was a multipart upload so we were forced to write a sha256 checksum as a custom header
    if (object.customMetadata?.[X_SIGNAL_CHECKSUM_SHA256] != null) {
        headers.set(X_SIGNAL_CHECKSUM_SHA256, object.customMetadata[X_SIGNAL_CHECKSUM_SHA256]);
    }

    return new Response(object.body, {headers});

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
    const handler = env.UPLOAD_HANDLER.get(env.UPLOAD_HANDLER.idFromName(requestId));
    return await handler.fetch(request.url, {
        body: request.body,
        method: request.method,
        headers: request.headers,
        signal: AbortSignal.timeout(DO_CALL_TIMEOUT)
    });
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
    if (!password) {
        return {state: 'error', error: error(400, 'invalid auth format')};
    }
    return {state: 'success', user: username, password: password};
}

// Checks the request is authenticated for the name provided in the request path :id segment
async function withAuthenticatedKey(request: IRequest, env: Env): Promise<Response | undefined> {
    return await authAgainstUploadName(request, env, request.params.bucket, request.params.id);
}

// Checks the request is authenticated for the name provided in the TUS upload-metadata
async function withAuthenticatedKeyFromMetadata(request: IRequest, env: Env): Promise<Response | undefined> {
    const key = parseUploadMetadata(request.headers).filename;
    if (key == null) {
        return error(400, 'upload-metadata filename required');
    }
    return await authAgainstUploadName(request, env, request.params.bucket, key);
}

// Checks the request is authenticated for key
async function authAgainstUploadName(request: IRequest, env: Env, bucket: string, key: string): Promise<Response | undefined> {
    auth = auth || await createAuth(env.SHARED_AUTH_SECRET, 3600 * 24 * 7);

    if (bucket !== env.PATH_PREFIX) {
        return error(404);
    }

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

    if (key === '') {
        return error(400, 'invalid upload name');
    }

    if (parsed.user !== bucket + '/' + key) {
        return error(401, 'invalid credentials for upload name');
    }
    request.key = key;
}

