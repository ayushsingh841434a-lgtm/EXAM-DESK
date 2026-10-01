import { AttemptStatus, ViolationType } from '@prisma/client';

export const STRICT_TERMINATION_VIOLATIONS = new Set<string>([
  'TAB_SWITCH',
  'WINDOW_BLUR',
  'FULLSCREEN_EXIT',
  'MULTIPLE_SESSION',
  'COPY_ATTEMPT',
  'PASTE_ATTEMPT',
  'CONTEXT_MENU_ATTEMPT',
]);

export const FINAL_ATTEMPT_STATUSES = new Set<string>([
  'SUBMITTED',
  'AUTO_SUBMITTED',
  'CANCELLED_VIOLATION',
  'TERMINATED_CHEATING',
]);

export function getViolationReason(type: ViolationType | string): string {
  switch (type) {
    case 'TAB_SWITCH':
      return 'TAB_SWITCH';
    case 'WINDOW_BLUR':
      return 'WINDOW_BLUR';
    case 'FULLSCREEN_EXIT':
      return 'FULLSCREEN_EXIT';
    case 'MULTIPLE_SESSION':
      return 'MULTIPLE_SESSION';
    case 'COPY_ATTEMPT':
      return 'COPY_ATTEMPT';
    case 'PASTE_ATTEMPT':
      return 'PASTE_ATTEMPT';
    case 'CONTEXT_MENU_ATTEMPT':
      return 'CONTEXT_MENU_ATTEMPT';
    default:
      return String(type || 'UNKNOWN');
  }
}

export function shouldTerminateOnViolation(type: ViolationType | string): boolean {
  return STRICT_TERMINATION_VIOLATIONS.has(String(type));
}
