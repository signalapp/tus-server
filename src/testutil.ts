// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {createAuth} from './auth';

export const attachmentsPath = 'attachments';
export const backupsPath = 'backups';

// Should match the secret in vitest.config.ts
export const secret = 'test';
export const auth = await createAuth(secret, 100);

export async function headerFor(key: string): Promise<string> {
    const user = `${attachmentsPath}/${key}`;
    const pass = await auth.generatePass(user);
    return `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
}

export async function backupHeaderFor(key: string, permission: string): Promise<string> {
    const user = `${permission}$${backupsPath}/${key}`;
    const pass = await auth.generatePass(user);
    return `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
}

