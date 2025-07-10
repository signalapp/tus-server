// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {defineConfig} from 'vitest/config';

export default defineConfig({
    test: {
        projects: [
            // Tests that use the vitest-pool-workers for workerd test runners
            'src/vitest.config.ts',
            // Tests that use the standard node test runners
            'e2e/vitest.config.e2e.ts'
        ]
    },
});
