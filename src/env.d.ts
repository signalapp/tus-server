// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

declare module 'cloudflare:test' {
    interface ProvidedEnv extends Env {
        ATTACHMENT_BUCKET: R2Bucket;
        BACKUP_BUCKET: R2Bucket;
        SHARED_AUTH_SECRET: string;
        ATTACHMENT_UPLOAD_HANDLER: DurableObjectNamespace;
        BACKUP_UPLOAD_HANDLER: DurableObjectNamespace;
    }
}
