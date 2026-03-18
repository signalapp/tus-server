// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {createAuth} from './auth';
import {SignJWT} from 'jose';
import {MAX_UPLOAD_LENGTH_BYTES} from './uploadHandler';

export const attachmentsPath = 'attachments';
export const backupsPath = 'backups';

// Should match the secret in vitest.config.ts
export const secret = 'test';
export const auth = await createAuth(secret, 100);
const jwtSecret = new Uint8Array(Buffer.from(secret, 'base64'));

export type AuthType = 'basic' | 'bearer';

export async function headerFor(key: string, type: AuthType = 'bearer', maxLen: number = MAX_UPLOAD_LENGTH_BYTES): Promise<string> {
    if (type === 'bearer') {
        const token = await new SignJWT({maxLen})
            .setProtectedHeader({alg: 'HS256'})
            .setSubject(key)
            .setAudience(attachmentsPath)
            .setIssuedAt()
            .sign(jwtSecret);
        return `Bearer ${token}`;
    } else {
        const user = `${attachmentsPath}/${key}`;
        const pass = await auth.generatePass(user);
        return `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
    }
}

export async function backupHeaderFor(key: string, permission: string, type: AuthType = 'bearer', maxLen: number = MAX_UPLOAD_LENGTH_BYTES): Promise<string> {
    if (type === 'bearer') {
        const token = await new SignJWT({scope: permission, maxLen})
            .setProtectedHeader({alg: 'HS256'})
            .setSubject(key)
            .setAudience(backupsPath)
            .setIssuedAt()
            .sign(jwtSecret);
        return `Bearer ${token}`;
    } else {
        const user = `${permission}$${backupsPath}/${key}`;
        const pass = await auth.generatePass(user);
        return `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
    }
}
