// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {defineConfig} from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'miniflare',
        environmentOptions: {
            modules: true,
            scriptPath: 'dist/index.js',
            durableObjects: {
                ATTACHMENT_UPLOAD_HANDLER: 'AttachmentUploadHandler',
                BACKUP_UPLOAD_HANDLER: 'BackupUploadHandler',
            },
        },
    },
});
