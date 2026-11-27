import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getAboutInfo, formatAboutOutput, runAbout } from '../../src/cli/commands/about.js';
import { createProgram } from '../../src/cli/index.js';
import { getDevPilotVersion } from '../../src/utils/version.js';

describe('DevPilot About Command', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  // 1. devpilot about executes successfully
  it('1. executes runAbout() successfully without errors', () => {
    expect(() => runAbout()).not.toThrow();
    expect(logSpy).toHaveBeenCalledTimes(1);
    const output = logSpy.mock.calls[0]?.[0] as string;
    expect(output).toBeDefined();
    expect(output.length).toBeGreaterThan(0);
  });

  // 2. Founder name is displayed correctly
  it('2. displays founder name (Pranay Khodade) correctly', () => {
    const info = getAboutInfo();
    expect(info.founderName).toBe('Pranay Khodade');

    const formatted = formatAboutOutput(info);
    expect(formatted).toContain('Pranay Khodade');
    expect(formatted).toContain('CREATED BY');
  });

  // 3. Founder title is displayed correctly
  it('3. displays founder title (Founder & Creator) correctly', () => {
    const info = getAboutInfo();
    expect(info.founderTitle).toBe('Founder & Creator');

    const formatted = formatAboutOutput(info);
    expect(formatted).toContain('Founder & Creator');
  });

  // 4. Project description and mission are displayed
  it('4. displays project description and mission correctly', () => {
    const info = getAboutInfo();
    expect(info.description).toContain('developer-friendly security toolkit');
    expect(info.mission).toContain('Help developers identify, understand, and fix security issues');

    const formatted = formatAboutOutput(info);
    expect(formatted).toContain('A developer-friendly security toolkit');
    expect(formatted).toContain('for modern applications.');
    expect(formatted).toContain('OUR MISSION');
    expect(formatted).toContain('Help developers identify, understand,');
    expect(formatted).toContain('and fix security issues in their projects.');
  });

  // 5. Version is dynamically obtained rather than hardcoded
  it('5. obtains version dynamically from package metadata rather than hardcoding', () => {
    const actualVersion = getDevPilotVersion();
    const info = getAboutInfo();
    expect(info.version).toBe(actualVersion);

    // Verify dynamic behavior with custom metadata
    const dynamicInfo = getAboutInfo({ version: '9.9.9' });
    expect(dynamicInfo.version).toBe('9.9.9');
    const formatted = formatAboutOutput(dynamicInfo);
    expect(formatted).toContain('9.9.9');
  });

  // 6. Repository URL is correct
  it('6. displays the correct GitHub repository URL', () => {
    const expectedRepo = 'https://github.com/pranaykhodade1922-dot/Devpilot';
    const info = getAboutInfo();
    expect(info.repositoryUrl).toBe(expectedRepo);

    const formatted = formatAboutOutput(info);
    expect(formatted).toContain(expectedRepo);
  });

  // 7. devpilot --help lists the about command
  it('7. lists the about command under UTILITY COMMANDS in devpilot --help', () => {
    const program = createProgram();
    const help = program.helpInformation();

    expect(help).toContain('UTILITY COMMANDS');
    expect(help).toContain('about');
    expect(help).toContain('Show information about DevPilot Security and its founder');

    // Also verify the Commander command definition exists
    const aboutCmd = program.commands.find((cmd) => cmd.name() === 'about');
    expect(aboutCmd).toBeDefined();
    expect(aboutCmd?.description()).toBe('Show information about DevPilot Security and its founder');
  });

  // 8. Existing commands remain unaffected
  it('8. ensures existing commands (scan, security, doctor) remain registered and unaffected', () => {
    const program = createProgram();
    const commandNames = program.commands.map((cmd) => cmd.name());

    expect(commandNames).toContain('scan');
    expect(commandNames).toContain('security');
    expect(commandNames).toContain('doctor');
    expect(commandNames).toContain('about');

    const securityCmd = program.commands.find((cmd) => cmd.name() === 'security');
    const secSubCommands = securityCmd?.commands.map((cmd) => cmd.name());
    expect(secSubCommands).toContain('deps');
    expect(secSubCommands).toContain('secrets');
  });

  // License verification
  it('displays verified license from package metadata when present', () => {
    const info = getAboutInfo();
    if (info.license) {
      const formatted = formatAboutOutput(info);
      expect(formatted).toContain('License:');
      expect(formatted).toContain(info.license);
    }
  });
});
