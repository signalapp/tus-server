// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// cloudflare:test currently has an issue where tests will fail if a non-empty body of a durable
// object response is not disposed of. See https://github.com/cloudflare/workers-sdk/issues/5629 . The
// superfluous `await response.body.cancel()` calls in some tests may be removed when this issue is fixed.

import {describe, expect, it, test} from 'vitest';
import {attachmentsPath, backupHeaderFor, backupsPath, headerFor} from './testutil';
import {SELF} from 'cloudflare:test';
import {X_SIGNAL_CHECKSUM_SHA256} from './uploadHandler';
import {toBase64} from './util';
import './env.d.ts';

const PART_SIZE = 1024 * 1024 * 5;

describe('worker auth', () => {
    it('rejects un-authd request', async () => {
        const res = await SELF.fetch(`http://localhost/upload/${attachmentsPath}/`, {
            method: 'POST',
            headers: {'Upload-Metadata': `filename ${btoa('test')}`}
        });
        expect(res.status).toBe(401);
    });

    it('rejects misformated auth', async () => {
        const res = await SELF.fetch(`http://localhost/upload/${attachmentsPath}/`, {
            method: 'POST',
            headers: {'Authorization': 'Complex zzzzz'}
        });
        expect(res.status).toBe(400);
    });

    it('accepts valid auth', async () => {
        const res = await SELF.fetch(`http://localhost/upload/${attachmentsPath}/`, {
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

    it('rejects backups POST with bad permission', async () => {
        const res = await SELF.fetch(`http://localhost/upload/${attachmentsPath}/`, {
            method: 'POST',
            headers: {
                'Upload-Metadata': `filename ${btoa('abc')}`,
                'Authorization': await backupHeaderFor('abc', 'read'),
                'Upload-Length': '1'
            }
        });
        expect(res.status).toBe(401);
    });

    it('accepts unauthd GET to attachments', async () => {
        const res = await SELF.fetch(`http://localhost/${attachmentsPath}/abc`);
        expect(res.status).toBe(404);
    });

    it('rejects unauthd GET to backups', async () => {
        const res = await SELF.fetch(`http://localhost/${backupsPath}/abc/def`);
        expect(res.status).toBe(401);
    });

    it('rejects GET to backups with no second component', async () => {
        const res = await SELF.fetch(`http://localhost/${backupsPath}/abc/`);
        expect(res.status).toBe(401);
    });

    it.each(['write', '', 'abc'])('rejects GET to backups with %s permission', async (permission) => {
        const res = await SELF.fetch(`http://localhost/${backupsPath}/abc/def`, {
            headers: {'Authorization': await backupHeaderFor('abc', permission)}
        });
        expect(res.status).toBe(401);
    });

    it.each(['ab', '/abc', 'abc/', '', 'abc/def'])('rejects GET with incorrect subdir %s', async (subdir) => {
        const res = await SELF.fetch(`http://localhost/${backupsPath}/abc/def`, {
            headers: {'Authorization': await backupHeaderFor(subdir, 'read')}
        });
        expect(res.status).toBe(401);
    });


    it('accepts subdir authd GET to backups', async () => {
        const res = await SELF.fetch(`http://localhost/${backupsPath}/abc/def`, {
            headers: {'Authorization': await backupHeaderFor('abc', 'read')}
        });
        expect(res.status).toBe(404);
    });
});

describe('request validation', () => {
    it('rejects bad checksum', async () => {
        const res = await SELF.fetch(`http://localhost/upload/${attachmentsPath}/`, {
            method: 'POST',
            headers: {
                'Upload-Metadata': `filename ${btoa('abc')}`,
                'Authorization': await headerFor('abc'),
                'Upload-Length': '1',
                [X_SIGNAL_CHECKSUM_SHA256]: 'AAAA'
            }
        });
        expect(res.status).toBe(400);
        await res.body?.cancel();
    });

    it('rejects no upload-length', async () => {
        const res = await SELF.fetch(`http://localhost/upload/${attachmentsPath}/`, {
            method: 'POST',
            headers: {
                'Upload-Metadata': `filename ${btoa('abc')}`,
                'Authorization': await headerFor('abc'),
            }
        });
        expect(res.status).toBe(400);
        await res.body?.cancel();
    });

    it('rejects missing content-type', async () => {
        const res = await SELF.fetch(`http://localhost/upload/${attachmentsPath}/`, {
            method: 'POST',
            // needs a content-type
            headers: {
                'Upload-Metadata': `filename ${btoa('abc')}`,
                'Authorization': await headerFor('abc'),
                'Upload-Length': '1',
                'Content-Length': '1'
            },
            body: 'a'
        });
        expect(res.status).toBe(415);
        await res.body?.cancel();
    });

    it('rejects bad content-type', async () => {
        const res = await SELF.fetch(`http://localhost/upload/${attachmentsPath}/`, {
            method: 'POST',
            headers: {
                'Upload-Metadata': `filename ${btoa('abc')}`,
                'Authorization': await headerFor('abc'),
                'Upload-Length': '1',
                // should be application/offset+octet-stream
                'Content-Type': 'application/octet-stream'
            },
        });
        expect(res.status).toBe(415);
        await res.body?.cancel();
    });

    it('accepts no trailing slash', async () => {
        const res = await SELF.fetch(`http://localhost/upload/${attachmentsPath}`, {
            method: 'POST',
            headers: {
                'Upload-Metadata': `filename ${btoa('abc')}`,
                'Authorization': await headerFor('abc'),
                'Upload-Length': '1',
            }
        });
        expect(res.status).toBe(201);
        expect(res.headers.get('location')).toBe(`http://localhost/upload/${attachmentsPath}/abc`);
        await res.body?.cancel();
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
        return await SELF.fetch(`http://localhost/upload/${attachmentsPath}/`, {
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

        return await SELF.fetch(`http://localhost/upload/${attachmentsPath}/${name}`, {
            method: 'PATCH',
            headers: h,
            duplex: 'half',
            body: body
        });
    }

    async function headRequest() {
        return SELF.fetch(`http://localhost/upload/${attachmentsPath}/${name}`, {
            method: 'HEAD',
            headers: {
                'Authorization': await headerFor(name),
                'Tus-Resumable': '1.0.0'
            }
        });
    }

    async function getRequest(headers?: Record<string, string>) {
        const h = headers || {};
        Object.assign(h, {
            'Authorization': await headerFor(name),
        });
        return await SELF.fetch(`http://localhost/${attachmentsPath}/${name}`, {
            method: 'GET',
            headers: h
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
        await patchRequest(0, body(8, {
            pattern: 'test',
            error: 'injected error',
            // write small chunks so the reader reads something before the error
            targetChunkSize: 4
        }));

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

        // Sending a request to the test workerd with an unconsumed body sometimes flakes. The
        // validation we're testing for happens before the body is used anyway, so just leave
        // it off until this issue is fixed.
        // https://github.com/cloudflare/workers-sdk/issues/3607
        // const upload = await patchRequest(4, 'ba');
        const upload = await patchRequest(4);
        expect(upload.status).toBe(409);
        await upload.body?.cancel();

        await patchRequest(3, 'bar');
        expect(await (await getRequest()).text()).toBe('foobar');
    });

    it('returns 200 for head of completed uploads', async () => {
        await createRequest({uploadLength: 4});
        await patchRequest(0, 'test');

        // https://tus.io/protocols/resumable-upload#head
        // The Server MUST always include the Upload-Offset header in the response for a HEAD request, even if the
        // offset is 0, or the upload is already considered completed.
        const head = await headRequest();
        expect(await head.text()).toBe('');
        expect(head.status).toBe(200);
        expect(head.headers.get('Upload-Offset')).toBe('4');
        expect(head.headers.get('Upload-Length')).toBe('4');
    });

    it('returns upload-length on head if it is known', async () => {
        await createRequest({uploadLength: 4});
        await patchRequest(0, 'te');

        let head = await headRequest();
        expect(await head.text()).toBe('');
        expect(head.status).toBe(200);
        expect(head.headers.get('Upload-Offset')).toBe('2');
        expect(head.headers.get('Upload-Length')).toBe('4');

        await patchRequest(2, 'st');

        head = await headRequest();
        expect(await head.text()).toBe('');
        expect(head.status).toBe(200);
        expect(head.headers.get('Upload-Offset')).toBe('4');
        expect(head.headers.get('Upload-Length')).toBe('4');
    });

    it('handles head with missing upload length', async () => {
        await createRequest();
        await patchRequest(0, 'te');

        let head = await headRequest();
        expect(await head.text()).toBe('');
        expect(head.status).toBe(200);
        expect(head.headers.get('Upload-Offset')).toBe('2');
        expect(head.headers.get('Upload-Length')).toBeNull();

        await patchRequest(2, 'st', {'Upload-Length': '4'});

        head = await headRequest();
        expect(await head.text()).toBe('');
        expect(head.status).toBe(200);
        expect(head.headers.get('Upload-Offset')).toBe('4');
        expect(head.headers.get('Upload-Length')).toBe('4');
    });

    it('handles ranged reads', async () => {
        const bytes = new Uint8Array(1000);
        crypto.getRandomValues(bytes);
        const body = Buffer.from(bytes).toString('base64');
        await createRequest({body: body, uploadLength: body.length});

        const prefixResponse = await getRequest({'range': 'bytes=0-371'});
        const prefix = await prefixResponse.text();
        expect(prefixResponse.status).toBe(206);
        expect(prefixResponse.headers.get('content-range')).toBe(`bytes 0-371/${body.length}`);
        expect(prefix).toEqual(body.slice(0, 372));

        const suffixResponse = await getRequest({'range': 'bytes=372-'});
        const suffix = await suffixResponse.text();
        expect(suffixResponse.status).toBe(206);
        expect(suffixResponse.headers.get('content-range')).toBe(`bytes 372-${body.length - 1}/${body.length}`);
        expect(suffix).toEqual(body.slice(372));
    });

    test.each(['nibbles=0-3', 'bytes=0-2,4-', 'bytes=zzz'])('ignores bad range: %s', async (arg: string) => {
        await createRequest({body: 'hello', uploadLength: 5});
        const response = await getRequest({'range': arg});
        expect(response.status).toBe(206);
        expect(await response.text()).toBe('hello');
    });

    it('handles suffix ranges', async () => {
        const bytes = new Uint8Array(1000);
        crypto.getRandomValues(bytes);
        const body = Buffer.from(bytes).toString('base64');
        await createRequest({body: body, uploadLength: body.length});
        const response = await getRequest({'range': 'bytes=-99'});
        expect(response.status).toBe(206);
        const responseText = await response.text();
        expect(responseText).toEqual(body.slice(body.length - 99, body.length));
        expect(response.headers.get('content-range')).toEqual(`bytes ${body.length - 99}-${body.length - 1}/${body.length}`);
    });

    test.each([1, 2, 17])('handles reading chunks of length=%s', async (chunkSize: number) => {
        const bytes = new Uint8Array(100);
        crypto.getRandomValues(bytes);
        const body = Buffer.from(bytes).toString('base64');
        await createRequest({body: body, uploadLength: body.length});

        let actual = '';
        for (let offset = 0; offset < body.length; offset += chunkSize) {
            const endIndex = Math.min(offset + chunkSize - 1, body.length - 1);
            const response = await getRequest({'range': `bytes=${offset}-${endIndex}`});
            expect(response.status).toBe(206);
            expect(response.headers.get('content-range')).toBe(`bytes ${offset}-${endIndex}/${body.length}`);
            actual += await response.text();
        }
        expect(actual).toEqual(body);
    }, {timeout: 60000});

    test.each(
        [0, 1, PART_SIZE - 1, PART_SIZE, PART_SIZE + 1]
    )('rejects incorrect checksum for length=%s', async (bodySize: number) => {
        await createRequest({uploadLength: bodySize, checksum: new Uint8Array(32)});
        const upload = await patchRequest(0, body(bodySize, {pattern: 'test'}));
        expect(upload.status).toBe(415);
        await upload.body?.cancel();

        // should delete the in-progress upload: if the object already existed, Upload-Offset should be the object
        // length. Otherwise, the head should 404.
        const head = await headRequest();
        if (head.status === 200) {
            expect(head.headers.get('Upload-Offset'))
                .toBe(head.headers.get('Upload-Length'));
        } else {
            expect(head.status).toBe(404);
        }
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
            const expectedChecksum = await sha256(body(bodySize, {pattern: 'test'}));
            await createRequest({uploadLength: bodySize, checksum: new Uint8Array(expectedChecksum)});
            if (multiplePatches) {
                await patchRequest(0, body(4, {pattern: 'test'}));
                await patchRequest(4, body(bodySize - 4, {pattern: 'test'}));

            } else {
                await patchRequest(0, body(bodySize, {pattern: 'test'}));
            }
            // make sure the checksum is also returned on GET
            const get = await getRequest();
            await get.body?.cancel();
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
        }, {timeout: 60000});

});


describe('completed object read operations', () => {
    test.each(['HEAD', 'GET'])('404s unknown %s object', async (method: string) => {
        const head = await SELF.fetch(`http://localhost/${backupsPath}/subdir/does_not_exist`, {
            method,
            headers: {'Authorization': await backupHeaderFor('subdir', 'read')}
        });
        expect(head.status).toBe(404);
    });

    test.each(['HEAD', 'GET'])('populates headers for %s object', async (method: string) => {
        const digest = toBase64(await sha256(body(4, {pattern: 'test'})));
        await SELF.fetch(`http://localhost/upload/${backupsPath}/`, {
            method: 'POST',
            headers: {
                'Authorization': await backupHeaderFor('subdir/a/b', 'write'),
                'Tus-Resumable': '1.0.0',
                'Upload-Metadata': `filename ${btoa('subdir/a/b')}`,
                'Upload-Length': '4',
                'Content-Type': 'application/offset+octet-stream',
                [X_SIGNAL_CHECKSUM_SHA256]: digest
            },
            duplex: 'half',
            body: body(4, {pattern: 'test'})
        });
        const resp = await SELF.fetch(`http://localhost/${backupsPath}/subdir/a/b`, {
            method: method,
            headers: {'Authorization': await backupHeaderFor('subdir', 'read')}
        });
        expect(resp.status).toBe(200);
        expect(resp.headers.get('etag')).toBe(await s3Etag(body(4, {pattern: 'test'})));
        expect(resp.headers.get(X_SIGNAL_CHECKSUM_SHA256)).toEqual(digest);

        const lastModified: Date = new Date(resp.headers.get('Last-Modified')!);
        expect(lastModified).toBeTruthy();
        const diffSeconds = Math.abs(new Date().getTime() - lastModified.getTime()) / 1000;
        expect(diffSeconds < 60).toBe(true);

        await resp.body?.cancel();
    });
});


describe('path routing', () => {
    async function upload(bucket: string, name: string, auth: string, body: Buffer): Promise<Response> {
        return await SELF.fetch(`http://localhost/upload/${bucket}/`, {
            method: 'POST',
            headers: {
                'Authorization': auth,
                'Tus-Resumable': '1.0.0',
                'Upload-Metadata': `filename ${btoa(name)}`,
                'Upload-Length': body.length.toString(),
                'Content-Type': 'application/offset+octet-stream'
            },
            body: body
        });
    }

    it('selects correct bucket', async () => {
        const attachmentName = 'subdir/attachmentName';
        const backupName = 'subdir/backupName';
        const attachmentBlob = Buffer.from('attachment123', 'utf-8');
        const backupBlob = Buffer.from('backup123', 'utf-8');

        // write the attachment to the attachments bucket, the backup to the backup bucket
        await upload(attachmentsPath, attachmentName, await headerFor(attachmentName), attachmentBlob);
        await upload(backupsPath, backupName, await backupHeaderFor(backupName, 'write'), backupBlob);

        // the attachments bucket should have the attachment but not the backup
        let resp = await SELF.fetch(`http://localhost/${attachmentsPath}/${attachmentName}`);
        expect(await resp.text()).toBe('attachment123');
        resp = await SELF.fetch(`http://localhost/${attachmentsPath}/${backupName}`);
        expect(resp.status).toBe(404);

        // the backup bucket should have the backup but not the attachment
        resp = await SELF.fetch(`http://localhost/${backupsPath}/${attachmentName}`, {
            headers: {'Authorization': await backupHeaderFor('subdir', 'read')}
        });
        expect(resp.status).toBe(404);
        resp = await SELF.fetch(`http://localhost/${backupsPath}/${backupName}`, {
            headers: {'Authorization': await backupHeaderFor('subdir', 'read')}
        });
        expect(await resp.text()).toBe('backup123');

    });
});

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

async function sha256(body: ReadableStream<Uint8Array>): Promise<ArrayBuffer> {
    const digestStream = new crypto.DigestStream('SHA-256');
    await body.pipeTo(digestStream);
    return await digestStream.digest;
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
        return `"${Buffer.from(md5sums[0]!).toString('hex')}"`;
    }
    const nestedMd5 = await crypto.subtle.digest('MD5', await new Blob(md5sums).arrayBuffer());
    return `"${Buffer.from(nestedMd5).toString('hex')}-${md5sums.length}"`;
}



