import { describe, expect, it } from 'vitest';
import { getViolationEventKey, isBlockedShortcut, shouldTerminateOnViolation } from './antiCheat';

describe('anti-cheat safeguards', () => {
  it('blocks copy, paste, cut, select-all, and view-source shortcuts', () => {
    expect(isBlockedShortcut({ ctrlKey: true, metaKey: false, key: 'c' })).toBe(true);
    expect(isBlockedShortcut({ ctrlKey: true, metaKey: false, key: 'v' })).toBe(true);
    expect(isBlockedShortcut({ ctrlKey: true, metaKey: false, key: 'x' })).toBe(true);
    expect(isBlockedShortcut({ ctrlKey: true, metaKey: false, key: 'a' })).toBe(true);
    expect(isBlockedShortcut({ ctrlKey: true, metaKey: false, key: 'u' })).toBe(true);
    expect(isBlockedShortcut({ ctrlKey: false, metaKey: true, key: 'c' })).toBe(true);
    expect(isBlockedShortcut({ ctrlKey: false, metaKey: true, key: 'x' })).toBe(true);
    expect(isBlockedShortcut({ ctrlKey: false, metaKey: true, key: 'v' })).toBe(true);
    expect(isBlockedShortcut({ ctrlKey: false, metaKey: true, key: 'a' })).toBe(true);
    expect(isBlockedShortcut({ ctrlKey: false, metaKey: true, key: 'u' })).toBe(true);
    expect(isBlockedShortcut({ ctrlKey: false, metaKey: false, key: 'c' })).toBe(false);
    expect(isBlockedShortcut({ ctrlKey: false, metaKey: false, key: 'a' })).toBe(false);
  });

  it('deduplicates events by violation type and key', () => {
    expect(getViolationEventKey('COPY_ATTEMPT', 'c')).toBe('COPY_ATTEMPT:c');
    expect(getViolationEventKey('TAB_SWITCH')).toBe('TAB_SWITCH');
  });

  it('terminates on strict focus and fullscreen violations', () => {
    expect(shouldTerminateOnViolation('TAB_SWITCH')).toBe(true);
    expect(shouldTerminateOnViolation('WINDOW_BLUR')).toBe(true);
    expect(shouldTerminateOnViolation('FULLSCREEN_EXIT')).toBe(true);
    expect(shouldTerminateOnViolation('COPY_ATTEMPT')).toBe(true);
    expect(shouldTerminateOnViolation('RESULTS_PAGE')).toBe(false);
  });
});
