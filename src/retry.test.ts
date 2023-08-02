import {describe, expect, it} from 'vitest';
import {retry} from './retry';

describe('retry', () => {
    it('retries errors', async () => {
        let count = 0;
        const actual = await retry(async () => {
            count += 1;
            if (count === 1) {
                throw 'error';
            }
            return count;
        }, {params: {maxRetries: 1, durationMillis: 0}});
        expect(actual).toBe(2);
    });

    it('exhausts retries', async () => {
        let count = 0;
        await expect(() => retry(async () => {
                count += 1;
                throw 'error';
            },
            {params: {maxRetries: 5, durationMillis: 0}}))
            .rejects.toThrowError('error');
        expect(count).toBe(6);
    });

    it('does backoff', async () => {
        let count = 0;
        const sleepTimes: number[] = [];
        await retry(async () => {
            count += 1;
            if (count <= 4) {
                throw 'error';
            }
        }, {
            params: {maxRetries: 4, durationMillis: 10},
            sleepFun: async (ms) => {
                sleepTimes.push(ms);
                return;
            }
        });
        expect(sleepTimes).toEqual([10, 20, 40, 80]);
        expect(count).toBe(5);
    });
});
