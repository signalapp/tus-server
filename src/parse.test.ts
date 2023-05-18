// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {describe, expect, it} from 'vitest';
import {parseUploadMetadata} from './parse';
import {StatusError} from 'itty-router';

describe('upload-metadata parsing', () => {
    it('parses valid data', () => {
        const checksum = new Uint8Array(32);
        crypto.getRandomValues(checksum);
        const uploadMetadata = parseUploadMetadata(new Headers({
            'Upload-Metadata': createUploadMetadata({'filename': 'name'})
        }));
        expect(uploadMetadata.filename).toBe('name');
    });

    it('rejects empty key', () => {
        expect(() => parseUploadMetadata(new Headers({
            'Upload-Metadata': ',filename abc'
        }))).toSatisfy(throwsStatusCode(400));
    });

    it('handles empty value', () => {
        expect(parseUploadMetadata(new Headers({
            'Upload-Metadata': `ignored,filename ${btoa('hello')}`
        })).filename).toBe('hello');
    });

    it('ignores unknown fields', () => {
        expect(parseUploadMetadata(new Headers({
            'Upload-Metadata': `ignored hi,filename ${btoa('hello')}`
        })).filename).toBe('hello');
    });

    function throwsStatusCode(statusCode: number): (value: (() => void)) => boolean {
        return f => {
            try {
                f();
                return false;
            } catch (e) {
                console.log(`expected error: ${e}`);
                return e instanceof StatusError && e.status == statusCode;
            }
        };
    }
});

function createUploadMetadata(metadata: Record<string, string | Uint8Array>): string {
    return Object.entries(metadata)
        .map(([key, value]) => {
            if (typeof value === 'string') {
                return `${key} ${btoa(value)}`;
            } else {
                return `${key} ${Buffer.from(value).toString('base64')}`;
            }
        })
        .join(',');
}
