// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {cloudflareTest} from '@cloudflare/vitest-pool-workers';
import {defineConfig} from 'vitest/config';

export default defineConfig({
    plugins: [
        cloudflareTest({
            main: './index.ts',
            wrangler: {configPath: '../wrangler.toml'},
            miniflare: {bindings: {SHARED_AUTH_SECRET: 'test'}},
        }),
    ],
});
