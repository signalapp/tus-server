// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// e2e tests that use an off-the-shelf TUS client. The TUS client requires an actual server listening
// somewhere, so they can't use worker called via vitest-pool-workers

import {afterAll, beforeAll, describe, expect, it, test} from 'vitest';
import * as tus from 'tus-js-client';
import {UploadOptions} from 'tus-js-client';
import {unstable_dev, UnstableDevWorker} from 'wrangler';
import {attachmentsPath, backupHeaderFor, backupsPath, headerFor, secret} from '../src/testutil';

let worker: UnstableDevWorker;

beforeAll(async () => {
    worker = await unstable_dev('src/index.ts', {
        experimental: {disableExperimentalWarning: true},
        vars: {SHARED_AUTH_SECRET: secret}
    });
});

afterAll(async () => {
    await worker.stop();
});

async function tusClientUpload(name: string, pathPrefix: string, authHeader: string, blob: Buffer, options?: UploadOptions) {
    await new Promise<void>((resolve, reject) => {
        // node tus.Upload takes Buffer but typescript bindings are wrong
        const upload = new tus.Upload(blob as unknown as Blob, {
            endpoint: `http://${worker.address}:${worker.port}/upload/${pathPrefix}/`,
            metadata: {'filename': name},
            headers: {'Authorization': authHeader},
            onError: reject,
            onSuccess: resolve,
            uploadSize: blob.length,
            ...options
        });
        upload.start();
    });
}

describe('tus-js-client-%s', () => {
    const name = 'test-client-obj';

    test.each([false, true])('uploads creation-with-upload=%s',
        async (uploadDataDuringCreation: boolean) => {
            const blob = Buffer.from('test', 'utf-8');
            await tusClientUpload(name, attachmentsPath, await headerFor(name), blob, {uploadDataDuringCreation: uploadDataDuringCreation});
            const resp = await worker.fetch(`http://localhost/${attachmentsPath}/${name}`);
            expect(await resp.text()).toBe('test');
        });

    it('accepts uploads with slashes', async () => {
        const blob = Buffer.from('test', 'utf-8');
        const name = 'subdir/b/c';
        await tusClientUpload(name, backupsPath, await backupHeaderFor(name, 'write'), blob);
        const resp = await worker.fetch(`http://localhost/${backupsPath}/${name}`, {
            headers: {'Authorization': await backupHeaderFor('subdir', 'read')}
        });
        expect(await resp.text()).toBe('test');
    });
});
