// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {expect, it, test, describe} from 'vitest';
import {runInDurableObject, env, runDurableObjectAlarm} from 'cloudflare:test';

const PART_SIZE = 1024 * 1024 * 5;

describe('uploadHandler', () => {
    const r2: R2Bucket = env.ATTACHMENT_BUCKET;
    const handler = env.ATTACHMENT_UPLOAD_HANDLER;

    async function expectStateEmpty(stub: DurableObjectStub): Promise<void> {
        await runInDurableObject(stub, async (instance, state) => {
            expect((await state.storage.list()).size).toBe(0);
        });
    }

    it('cleans after alarms', async () => {
        const id = handler.newUniqueId();
        const stub = handler.get(id);

        await stub.fetch('http://localhost/upload/bucket/', {
            method: 'POST',
            headers: {
                'Upload-Metadata': `filename ${btoa('test123')}`,
                'Upload-Length': '10'
            }
        });
        await runInDurableObject(stub, async (instance, state) => {
            expect(await state.storage.get('upload-info')).toMatchObject({uploadLength: 10});
            expect(await state.storage.get('upload-offset')).toBe(0);
        });
        expect(await runDurableObjectAlarm(stub)).toBe(true);
        await expectStateEmpty(stub);
    });

    it('cleans after unrecoverable failure', async () => {
        const id = handler.idFromName('test123');
        const stub = handler.get(id);
        await runInDurableObject(stub, async (instance, state) => {
            const storage = state.storage;

            // invalid state: temp object should be length 5, is only length 1
            const tempkey = `temporary/${id.toString()}`;
            await r2.put(tempkey, '1');
            await storage.put('upload-info', {uploadLength: 10});
            await storage.put('upload-offset', 5);
        });

        await expect(() => stub.fetch('http://localhost/upload/bucket/test123', {
            method: 'PATCH',
            headers: {'Upload-Offset': '5'},
            body: '6789!'
        })).rejects.toThrowError();

        // should clean up after unrecoverable error
        await expectStateEmpty(stub);
    });

    it('cleans after a bad multipart tx', async () => {
        const id = handler.idFromName('test123');
        const stub = handler.get(id);
        await runInDurableObject(stub, async (instance, state) => {
            const storage = state.storage;

            // invalid state: we claim to have a part written but the transaction won't exist
            await storage.put('upload-info', {
                uploadLength: 10,
                multipartUploadId: 'fake-tx-id'
            });
            await storage.put('upload-offset', 5);
            await storage.put('1', {
                part: {partNumber: 1, etag: 'fake'},
                length: 5
            });
        });

        await expect(() => stub.fetch('http://localhost/upload/bucket/test123', {
            method: 'PATCH',
            headers: {'Upload-Offset': '5'},
            body: '12345'
        })).rejects.toThrowError('multipart upload does not exist');

        // should clean up after unrecoverable error
        await expectStateEmpty(stub);
    });

    it('hydrates from cold storage', async () => {
        const id = handler.idFromName('test123');
        const tempkey = `temporary/${id.toString()}`;
        await r2.put(tempkey, '12345');
        const stub = handler.get(id);
        await runInDurableObject(stub, async (instance, state) => {
            const storage = state.storage;
            await storage.put('upload-info', {uploadLength: 10});
            await storage.put('upload-offset', 5);
        });

        const resp = await stub.fetch('http://localhost/upload/bucket/test123', {
            method: 'PATCH',
            headers: {'Upload-Offset': '5'},
            body: '6789!'
        });
        expect(resp.status).toBe(204);

        const obj = await r2.get('test123');
        expect(obj).toBeTruthy();
        expect(await obj?.text()).toBe('123456789!');

        // temporary should be gone
        expect(await r2.get(tempkey)).toBeNull();

        // all keys should be gone after success
        await expectStateEmpty(stub);
    });

    it('hydrates tx parts from cold storage', async () => {
        const id = handler.idFromName('test123');
        const stub = handler.get(id);

        const partBody = new Uint8Array(PART_SIZE);
        const tempkey = `temporary/${id.toString()}`;
        const mp = await r2.createMultipartUpload('test123');
        const part1 = await mp.uploadPart(1, partBody);
        await r2.put(tempkey, '12345');

        runInDurableObject(stub, async (instance, state) => {
            const storage = state.storage;
            await storage.put('upload-offset', partBody.length + 5);
            await storage.put('upload-info', {
                uploadLength: partBody.length + 10,
                multipartUploadId: mp.uploadId
            });
            await storage.put('1', {
                part: part1,
                length: partBody.byteLength
            });
        });

        const resp = await stub.fetch('http://localhost/upload/bucket/test123', {
            method: 'PATCH',
            headers: {'Upload-Offset': (partBody.byteLength + 5).toString()},
            body: '6789!'
        });
        expect(resp.status).toBe(204);

        const obj = await r2.get('test123');
        expect(obj).toBeTruthy();
        const read = await obj?.text();
        expect(read?.length).toBe(partBody.byteLength + 10);
        expect(read?.slice(partBody.length, partBody.length + 10)).toBe('123456789!');

        // temporary should be gone
        expect(await r2.get(tempkey)).toBeNull();
        // all keys should be gone after success
        await expectStateEmpty(stub);
    });

    test.each(
        [
            [PART_SIZE, 1, 1],
            [PART_SIZE + 1, PART_SIZE, 1],
            [0, PART_SIZE + 1, 1],
            [0, 10, 10],
            [0, 10, PART_SIZE]
        ]
    )('resumes from storage for chunks=[%s,%s,%s]', async (chunk1Size, chunk2Size, chunk3Size) => {
        const firstChunk = new Uint8Array(chunk1Size);
        const secondChunk = new Uint8Array(chunk2Size);
        const thirdChunk = new Uint8Array(chunk3Size);

        const totalLength = firstChunk.length + secondChunk.length + thirdChunk.length;

        const id = handler.idFromName('test123');
        let stub = handler.get(id);
        await stub.fetch(new Request('http://localhost/upload/bucket', {
            method: 'POST',
            headers: {
                'Upload-Metadata': `filename ${btoa('test123')}`,
                'Upload-Length': totalLength.toString(),
                'Content-Type': 'application/offset+octet-stream'
            },
            body: firstChunk
        }));

        await stub.fetch(new Request('http://localhost/upload/bucket/test123', {
            method: 'PATCH',
            headers: {'Upload-Offset': firstChunk.length.toString()},
            body: secondChunk
        }));

        // create a new object from the same state
        stub = handler.get(id);
        await stub.fetch(new Request('http://localhost/upload/bucket/test123', {
            method: 'PATCH',
            body: thirdChunk,
            headers: {'Upload-Offset': (firstChunk.length + secondChunk.length).toString()}
        }));

        const obj = await r2.get('test123');
        expect((await obj?.text())?.length).toBe(totalLength);
    });
});