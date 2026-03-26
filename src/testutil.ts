// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {SignJWT} from 'jose';

export const attachmentsPath = 'attachments';
export const backupsPath = 'backups';

// Should match the secret in vitest.config.ts
export const secret = 'test';
const jwtSecret = new Uint8Array(Buffer.from(secret, 'base64'));

export async function headerFor(key: string, maxLen: number = 1024 * 1024 * 100): Promise<string> {
    const token = await new SignJWT({maxLen})
        .setProtectedHeader({alg: 'HS256'})
        .setSubject(key)
        .setAudience(attachmentsPath)
        .setIssuedAt()
        .sign(jwtSecret);
    return `Bearer ${token}`;
}

export async function backupHeaderFor(key: string, permission: string, maxLen: number = 1024 * 1024 * 100): Promise<string> {
    const token = await new SignJWT({scope: permission, maxLen})
        .setProtectedHeader({alg: 'HS256'})
        .setSubject(key)
        .setAudience(backupsPath)
        .setIssuedAt()
        .sign(jwtSecret);
    return `Bearer ${token}`;
}
