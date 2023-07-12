// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {expect, it, beforeAll, afterAll, describe, test} from 'vitest';
import {createAuth} from './auth';
import * as tus from 'tus-js-client';
import {unstable_dev, UnstableDevWorker} from 'wrangler';
import {X_SIGNAL_CHECKSUM_SHA256} from './uploadHandler';
import {toBase64} from './util';

const prefix = 'bucket';
const secret = 'test';
const auth = await createAuth(secret, 100);

const PART_SIZE = 1024 * 1024 * 5;

let worker: UnstableDevWorker;

beforeAll(async () => {
    worker = await unstable_dev('src/index.ts', {
        experimental: {disableExperimentalWarning: true},
        vars: {
            SHARED_AUTH_SECRET: secret,
            PATH_PREFIX: prefix
        }
    });
});

afterAll(async () => {
    await worker.stop();
});

describe('worker auth', () => {
    it('rejects un-authd request', async () => {
        const res = await worker.fetch(`http://localhost/upload/${prefix}/`, {
            method: 'POST',
            headers: {'Upload-Metadata': `filename ${btoa('test')}`}
        });
        expect(res.status).toBe(401);
    });

    it('rejects misformated auth', async () => {
        const res = await worker.fetch(`http://localhost/upload/${prefix}/`, {
            method: 'POST',
            headers: {'Authorization': 'Complex zzzzz'}
        });
        expect(res.status).toBe(400);
    });

    it('accepts valid auth', async () => {
        const res = await worker.fetch(`http://localhost/upload/${prefix}/`, {
            method: 'POST',
            headers: {
                'Upload-Metadata': `filename ${btoa('abc')}`,
                'Authorization': await headerFor('abc'),
                'Upload-Length': '1'
            }
        });
        expect(await res.text()).toBe('');
        expect(res.status).toBe(201);
    });
});

describe('request validation', () => {
    it('rejects bad checksum', async () => {
        const res = await worker.fetch(`http://localhost/upload/${prefix}/`, {
            method: 'POST',
            headers: {
                'Upload-Metadata': `filename ${btoa('abc')}`,
                'Authorization': await headerFor('abc'),
                'Upload-Length': '1',
                [X_SIGNAL_CHECKSUM_SHA256]: 'AAAA'
            }
        });
        expect(res.status).toBe(400);
    });

    it('rejects no upload-length', async () => {
        const res = await worker.fetch(`http://localhost/upload/${prefix}/`, {
            method: 'POST',
            headers: {
                'Upload-Metadata': `filename ${btoa('abc')}`,
                'Authorization': await headerFor('abc'),
            }
        });
        expect(res.status).toBe(400);
    });
});


describe('Tus', () => {
    const name = 'test123';

    interface CreateOptions {
        uploadLength?: number;
        body?: string;
        checksum?: Uint8Array;
    }

    async function createRequest(opts?: CreateOptions) {
        const headers: Record<string, string> = {
            'Authorization': await headerFor(name),
            'Tus-Resumable': '1.0.0',
            'Upload-Metadata': `filename ${btoa(name)}`
        };
        if (opts?.uploadLength != null) {
            headers['Upload-Length'] = opts.uploadLength.toString();
        } else {
            headers['Upload-Defer-Length'] = '1';
        }
        if (opts?.checksum != null) {
            headers[X_SIGNAL_CHECKSUM_SHA256] = toBase64(opts?.checksum);
        }
        if (opts?.body != null) {
            headers['Content-Type'] = 'application/offset+octet-stream';
        }
        return await worker.fetch(`http://localhost/upload/${prefix}/`, {
            method: 'POST',
            headers: headers,
            body: opts?.body
        });
    }

    async function patchRequest(uploadOffset: number, body?: string | ReadableStream<Uint8Array>, headers?: Record<string, string>) {
        const h = headers || {};
        Object.assign(h, {
            'Authorization': await headerFor(name),
            'Upload-Offset': uploadOffset.toString(),
            'Content-Type': 'application/offset+octet-stream',
            'Tus-Resumable': '1.0.0'
        });

        return await worker.fetch(`http://localhost/upload/${prefix}/${name}`, {
            method: 'PATCH',
            headers: h,
            duplex: 'half',
            body: body
        });
    }

    async function headRequest() {
        return worker.fetch(`http://localhost/upload/${prefix}/${name}`, {
            method: 'HEAD',
            headers: {
                'Authorization': await headerFor(name),
                'Tus-Resumable': '1.0.0'
            }
        });
    }

    async function getRequest() {
        return await worker.fetch(`http://localhost/${prefix}/${name}`, {
            method: 'GET',
            headers: {
                'Authorization': await headerFor(name),
            }
        });
    }

    it('accepts an upload', async () => {
        const create = await createRequest({uploadLength: 4});
        expect(await create.text()).toBe('');
        expect(create.status).toBe(201);

        const upload = await patchRequest(0, 'test');
        expect(await upload.text()).toBe('');
        expect(upload.status).toBe(204);
        expect(upload.headers.get('Upload-Offset')).toBe('4');
    });

    it('can defer length', async () => {
        const create = await createRequest();

        expect(await create.text()).toBe('');
        expect(create.status).toBe(201);

        const upload1 = await patchRequest(0, 'test');
        expect(upload1.status).toBe(204);
        const upload2 = await patchRequest(4, 'test');
        expect(upload2.status).toBe(204);
        const upload3 = await patchRequest(8, 'test', {'Upload-Length': '12'});
        expect(upload3.status).toBe(204);

        const get = await getRequest();
        expect(await get.text()).toBe('testtesttest');
        expect(get.status).toBe(200);
    });

    it('can defer length and finish with an empty body', async () => {
        const create = await createRequest();

        expect(await create.text()).toBe('');
        expect(create.status).toBe(201);

        const upload1 = await patchRequest(0, 'test');
        expect(upload1.status).toBe(204);
        expect(upload1.headers.get('Upload-Offset')).toBe('4');

        const upload2 = await patchRequest(4, '', {'Upload-Length': '4'});
        expect(upload2.status).toBe(204);
        expect(upload2.headers.get('Upload-Offset')).toBe('4');

        const get = await getRequest();
        expect(await get.text()).toBe('test');
        expect(get.status).toBe(200);
    });

    it('can upload in chunks', async () => {
        const create = await createRequest({uploadLength: 8});
        expect(create.status).toBe(201);

        let upload = await patchRequest(0, 'test');
        expect(upload.status).toBe(204);
        expect(upload.headers.get('Upload-Offset')).toBe('4');

        const head = await headRequest();
        expect(head.status).toBe(200);
        expect(head.headers.get('Upload-Offset')).toBe('4');

        upload = await patchRequest(4, 'test');
        expect(upload.statusText).toBe('No Content');
        expect(upload.status).toBe(204);

        const get = await getRequest();
        expect(await get.text()).toBe('testtest');
        expect(get.status).toBe(200);
    });

    it('can resume after interruption', async () => {
        const create = await createRequest({uploadLength: 16});
        expect(create.status).toBe(201);

        // body errors after first 8 bytes
        await expect(() => patchRequest(0, body(8, {
            pattern: 'test',
            error: 'injected error',
            // write small chunks so the reader reads something before the error
            targetChunkSize: 4
        }))).rejects.toThrowError();

        const head = await headRequest();
        expect(head.status).toBe(200);
        expect(head.headers.get('Upload-Offset')).toBe('8');

        // upload the rest
        const upload = await patchRequest(8, 'testtest');
        expect(upload.status).toBe(204);

        const get = await getRequest();
        expect(await get.text()).toBe('testtesttesttest');
    });

    it('can do a partial upload during creation', async () => {
        const create = await createRequest({uploadLength: 6, body: 'foo'});
        expect(create.status).toBe(201);
        expect(create.headers.get('Upload-Offset')).toBe('3');
        expect((await headRequest()).headers.get('Upload-Offset')).toBe('3');

        const upload = await patchRequest(3, 'bar');
        expect(upload.status).toBe(204);

        const get = await getRequest();
        expect(await get.text()).toBe('foobar');
    });

    it('rejects bad upload-offset', async () => {
        const create = await createRequest({uploadLength: 6, body: 'foo'});
        expect(create.status).toBe(201);
        expect(create.headers.get('Upload-Offset')).toBe('3');

        const upload = await patchRequest(4, 'ba');
        expect(upload.status).toBe(409);

        await patchRequest(3, 'bar');
        expect(await (await getRequest()).text()).toBe('foobar');
    });

    test.each(
        [0, 1, PART_SIZE - 1, PART_SIZE, PART_SIZE + 1]
    )('rejects incorrect checksum for length=%s', async (bodySize: number) => {
        await createRequest({uploadLength: bodySize, checksum: new Uint8Array(32)});
        const upload = await patchRequest(0, body(bodySize, {pattern: 'test'}));
        expect(upload.status).toBe(415);

        // should delete the in-progress upload
        expect((await headRequest()).status).toBe(404);
    });

    test.each(
        [
            [100, false],
            [100, true],
            [PART_SIZE + 1, false],
            [PART_SIZE + 1, true]
        ]
    )('accepts correct checksum for length=%s, multiple-patches=%s)',
        async (bodySize: number, multiplePatches: boolean) => {
            const digestStream = new crypto.DigestStream('SHA-256');
            await body(bodySize, {pattern: 'test'}).pipeTo(digestStream);
            const expectedChecksum = await digestStream.digest;

            await createRequest({uploadLength: bodySize, checksum: new Uint8Array(expectedChecksum)});
            if (multiplePatches) {
                await patchRequest(0, body(4, {pattern: 'test'}));
                await patchRequest(4, body(bodySize - 4, {pattern: 'test'}));

            } else {
                await patchRequest(0, body(bodySize, {pattern: 'test'}));
            }

            // make sure the checksum is also returned on GET
            const get = await getRequest();
            const actualChecksum = Buffer.from(get.headers.get(X_SIGNAL_CHECKSUM_SHA256) || '', 'base64');
            expect(actualChecksum.buffer).toEqual(expectedChecksum);
        });

    // parameterized test of boundary conditions
    test.each(
        [0, 1, PART_SIZE - 1, PART_SIZE, PART_SIZE + 1, PART_SIZE * 10 + 1]
    )('upload(%s bytes)',
        async (uploadSize) => {
            const create = await createRequest({uploadLength: uploadSize});
            expect(create.status).toBe(201);

            const upload = await patchRequest(0, body(uploadSize, {pattern: 'test'}));
            expect(upload.status).toBe(204);
            expect(upload.headers.get('Upload-Offset')).toBe(uploadSize.toString());

            const get = await getRequest();
            const read = await get.text();
            expect(bodyMatchesPattern(read, 'test')).toBe(true);

            const expectedEtag = await s3Etag(body(uploadSize, {pattern: 'test'}));
            expect(get.headers.get('etag')).toBe(expectedEtag);
        }, {timeout: 10000});

});


describe('tus-js-client', () => {
    const name = 'test-client-obj';

    test.each([false, true])('uploads creation-with-upload=%s',
        async (uploadDataDuringCreation: boolean) => {
            const blob = Buffer.from('test', 'utf-8');
            const authHeader = await headerFor(name);

            await new Promise<void>((resolve, reject) => {
                // node tus.Upload takes Buffer but typescript bindings are wrong
                const upload = new tus.Upload(blob as never as Blob, {
                    endpoint: `http://${worker.address}:${worker.port}/upload/${prefix}/`,
                    metadata: {'filename': name},
                    headers: {'Authorization': authHeader},
                    onError: reject,
                    onSuccess: resolve,
                    uploadSize: 4,
                    uploadDataDuringCreation: uploadDataDuringCreation
                });
                upload.start();
            });

            const resp = await fetch(`http://${worker.address}:${worker.port}/${prefix}/${name}`);
            expect(await resp.text()).toBe('test');
        });
});

async function headerFor(key: string): Promise<string> {
    const user = `${prefix}/${key}`;
    const pass = await auth.generatePass(user);
    return `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
}

function fillPattern(targetSize: number, pattern: string): Uint8Array {
    const patternBytes = new TextEncoder().encode(pattern);
    if (patternBytes.byteLength >= targetSize) {
        return patternBytes;
    }

    const repeatCount = Math.floor(targetSize / pattern.length);
    const chunk = new Uint8Array(repeatCount * patternBytes.byteLength);
    for (let i = 0; i < repeatCount; i++) {
        chunk.set(patternBytes, i * patternBytes.byteLength);
    }
    return chunk;
}

function bodyMatchesPattern(body: string, pattern: string): boolean {
    for (let offset = 0; offset < body.length; offset += pattern.length) {
        const remaining = body.length - offset;
        if (body.slice(offset, offset + pattern.length) !== pattern.slice(0, remaining)) {
            return false;
        }

    }
    return true;
}

interface BodyOptions {
    error?: string,
    pattern?: string,
    targetChunkSize?: number
}

function body(numBytes: number, bodyOptions?: BodyOptions): ReadableStream<Uint8Array> {
    const chunkSize = bodyOptions?.targetChunkSize || 4096;
    const chunk = bodyOptions?.pattern == null
        ? new Uint8Array(chunkSize)
        : fillPattern(chunkSize, bodyOptions.pattern);

    const queueChunk = (controller: ReadableStreamDefaultController) => {
        if (numBytes >= chunk.length) {
            numBytes -= chunk.length;
            controller.enqueue(chunk);
            return;
        }

        if (numBytes > 0) {
            controller.enqueue(chunk.subarray(0, numBytes));
        }
        if (bodyOptions?.error != null) {
            controller.error(bodyOptions?.error);
        } else {
            controller.close();
        }
    };

    return new ReadableStream({
        start(controller) {
            queueChunk(controller);
        },
        pull(controller) {
            queueChunk(controller);
        }
    });
}

// This implements the undocumented but de-facto standard algorithm S3 (and R2) uses
// to compute etags. If the object was uploaded without multi-part upload, it is
// the hex md5 of the object's bytes. If it was uploaded with multi-part, it is
// hex(md5(md5(part 1), md5(part 2) ...))-numParts
async function s3Etag(body: ReadableStream<Uint8Array>): Promise<string> {
    const md5sums: ArrayBuffer[] = [];
    const mem = new Uint8Array(PART_SIZE);
    let offset = 0;
    for await (let chunk of body) {
        while (chunk.byteLength > 0) {
            const toCopy = Math.min(PART_SIZE - offset, chunk.byteLength);
            mem.set(chunk.subarray(0, toCopy), offset);
            offset += toCopy;
            chunk = chunk.subarray(toCopy, chunk.byteLength);
            if (offset === PART_SIZE && chunk.byteLength > 0) {
                md5sums.push(await crypto.subtle.digest('MD5', mem));
                offset = 0;
            }
        }
    }
    md5sums.push(await crypto.subtle.digest('md5', mem.subarray(0, offset)));
    if (md5sums.length == 1) {
        return `"${Buffer.from(md5sums[0]).toString('hex')}"`;
    }
    const nestedMd5 = await crypto.subtle.digest('MD5', await new Blob(md5sums).arrayBuffer());
    return `"${Buffer.from(nestedMd5).toString('hex')}-${md5sums.length}"`;
}



