// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {defineWorkersConfig} from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig({
    test: {
        poolOptions: {
            workers: {
                main: './index.ts',
                wrangler: {configPath: '../wrangler.toml'},
                miniflare: {bindings: {SHARED_AUTH_SECRET: 'test'}},
            }
        },
    },
});
