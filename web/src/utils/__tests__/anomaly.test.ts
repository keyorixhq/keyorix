import { describe, it, expect } from 'vitest';
import { humanizeAlertType } from '../anomaly';

describe('humanizeAlertType', () => {
    it('maps the known anomaly types to readable labels', () => {
        expect(humanizeAlertType('off_hours')).toBe('Off-hours');
        expect(humanizeAlertType('new_ip')).toBe('New IP');
        expect(humanizeAlertType('new_user')).toBe('New user');
        expect(humanizeAlertType('frequency_spike')).toBe('Frequency spike');
    });

    it('title-cases an unknown snake_case type', () => {
        expect(humanizeAlertType('mass_export')).toBe('Mass Export');
        expect(humanizeAlertType('weird')).toBe('Weird');
    });
});
