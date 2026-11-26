import { describe, it, expect } from 'vitest';
import { getDoctorInfo } from '../src/cli/commands/doctor.js';

describe('Doctor Command', () => {
  it('returns valid environment diagnostic information', () => {
    const info = getDoctorInfo();

    expect(info.devPilotVersion).toBeDefined();
    expect(typeof info.devPilotVersion).toBe('string');
    expect(info.nodeVersion).toBe(process.version);
    expect(info.osPlatform).toBe(process.platform);
    expect(typeof info.osRelease).toBe('string');
    expect(typeof info.osArch).toBe('string');
    expect(info.cwd).toBe(process.cwd());
    expect(typeof info.isNodeSupported).toBe('boolean');
    expect(typeof info.environmentStatus).toBe('string');
  });
});
