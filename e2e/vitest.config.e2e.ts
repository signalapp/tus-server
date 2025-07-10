// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// The e2e tests use a standard node test runner instead of vitest-pool-workers, since they launch an entire listening
// worker
import {defineConfig} from 'vitest/config';

export default defineConfig({});
