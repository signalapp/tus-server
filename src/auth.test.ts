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
});
