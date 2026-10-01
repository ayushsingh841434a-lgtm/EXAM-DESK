export type ViolationType =
  | 'TAB_SWITCH'
  | 'WINDOW_BLUR'
  | 'FULLSCREEN_EXIT'
  | 'MULTIPLE_SESSION'
  | 'COPY_ATTEMPT'
  | 'PASTE_ATTEMPT'
  | 'CONTEXT_MENU_ATTEMPT';

export const BLOCKED_SHORTCUTS = new Set(['c', 'x', 'v', 'a', 'u']);
export const STRICT_TERMINATION_VIOLATIONS = new Set<string>([
  'TAB_SWITCH',
  'WINDOW_BLUR',
  'FULLSCREEN_EXIT',
  'MULTIPLE_SESSION',
  'COPY_ATTEMPT',
  'PASTE_ATTEMPT',
  'CONTEXT_MENU_ATTEMPT',
]);

export function isBlockedShortcut(event: Pick<KeyboardEvent, 'ctrlKey' | 'metaKey' | 'key'>): boolean {
  const key = event.key?.toLowerCase?.() ?? '';
  return (event.ctrlKey || event.metaKey) && BLOCKED_SHORTCUTS.has(key);
}

export function getViolationEventKey(type: string, detail?: string): string {
  return detail ? `${type}:${String(detail).toLowerCase()}` : type;
}

export function shouldTerminateOnViolation(type: string): boolean {
  return STRICT_TERMINATION_VIOLATIONS.has(type);
}

export function getTerminationMessage(): string {
  return 'Exam Terminated\nYou left the exam window or switched to another tab/window.\nYour exam has been automatically terminated due to the exam\'s anti-cheating policy.';
}
