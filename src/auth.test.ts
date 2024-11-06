// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {describe, expect, it} from 'vitest';
import {createAuthWithClock} from './auth';

describe('Auth', async () => {
    const user = 'test';
    const secret = 'secret';
    const maxAge = 10;

    async function generatePassAt(user: string, time: number): Promise<string> {
        const auth = await createAuthWithClock(secret, maxAge, () => time);
        return await auth.generatePass(user);
    }

    async function validateAt(user: string, password: string, time: number): Promise<boolean> {
        const auth = await createAuthWithClock(secret, maxAge, () => time);
        return await auth.validateCredentials(user, password);
    }

    it('rejects expired credentials', async () => {
        expect(await validateAt(user, await generatePassAt(user, 1), 12)).toBe(false);
    });

    it('passes valid credentials', async () => {
        expect(await validateAt(user, await generatePassAt(user, 1), 11)).toBe(true);
    });

    it('rejects wrong-user credentials', async () => {
        expect(await validateAt(user, await generatePassAt(user + 'a', 1), 1)).toBe(false);
    });

    it('rejects missing signature', async () => {
        let pass = await generatePassAt(user, 1);
        // pass is ts:hex-sig, remove the signature
        pass = pass.substring(0, pass.indexOf(':'));
        expect(await validateAt(user, pass, 11)).toBe(false);
    });

    it('rejects long signature', async () => {
        let pass = await generatePassAt(user, 1);
        // pass is ts:hex-sig, change the sig length
        pass += 'aa';
        expect(await validateAt(user, pass, 11)).toBe(false);
    });

    it('rejects short signature', async () => {
        let pass = await generatePassAt(user, 1);
        // pass is ts:hex-sig, change the sig length
        pass = pass.slice(0, pass.length - 1);
        expect(await validateAt(user, pass, 11)).toBe(false);
    });
});
