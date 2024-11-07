// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {describe, expect, it} from 'vitest';
import {AsyncLock, Release, WritableStreamBuffer} from './util';

describe('WritableStreamBuffer', () => {
    it('copies what fits', async () => {
        const st = new WritableStreamBuffer(new ArrayBuffer(10));
        const written = st.writeUpTo(new Uint8Array(new ArrayBuffer(11)));
        expect(written).toBe(10);
        expect(st.offset).toBe(10);

        expect(st.writeUpTo(new Uint8Array(new ArrayBuffer(1)))).toBe(0);
        expect(st.offset).toBe(10);
    });
});

describe('AsyncLock', () => {
    it('only lets one through', async () => {
        const lock = new AsyncLock();
        const release = await lock.lock();
        const queued = lock.lock();
        let done = false;
        queued.then(() => done = true);

        expect(done).toBeFalsy();
        release();
        await queued;
        expect(done).toBeTruthy();
    });

    it('can queue waiters', async () => {
        const lock = new AsyncLock();
        let release = await lock.lock();

        // queue up 10 requests behind currently executing one
        const waiters: { promise: Promise<Release>, done: boolean }[] = [];
        for (let i = 0; i < 10; i++) {
            const waiter = {
                promise: lock.lock(),
                done: false
            };
            waiter.promise.then(() => waiter.done = true);
            waiters.push(waiter);
        }
        expect(waiters.every(waiter => !waiter.done)).toBeTruthy();

        // finishing previous request should allow next one to proceed
        for (let i = 0; i < 10; i++) {
            release();
            release = await (waiters[i]!.promise);
            expect(waiters.slice(i + 1).every(waiter => !waiter.done)).toBeTruthy();
        }
    });
});
