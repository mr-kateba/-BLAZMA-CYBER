// Local, offline password observations ("tips"). Pure and platform-neutral so the renderer can show
// them while the user types without the password leaving the window. This is deliberately NOT a
// strength score: it lists concrete, verifiable weaknesses and nothing else.

export type PasswordTip = 'too_short' | 'few_kinds' | 'only_digits' | 'repeated' | 'sequence' | 'keyboard' | 'year';

export interface PasswordTips {
  /** Length in characters (code points, so Arabic and emoji count once). */
  length: number;
  /** Kinds of characters used: lowercase, uppercase, digits, symbols, other letters (e.g. Arabic). */
  kinds: number;
  tips: PasswordTip[];
}

const SEQUENCES = ['0123456789', 'abcdefghijklmnopqrstuvwxyz'];
const KEYBOARD = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx', 'qwertz', 'azerty'];

function hasRun(lower: string, alphabet: string, len: number): boolean {
  const rev = [...alphabet].reverse().join('');
  for (let i = 0; i + len <= lower.length; i++) {
    const part = lower.slice(i, i + len);
    if (alphabet.includes(part) || rev.includes(part)) return true;
  }
  return false;
}

export function passwordTips(pw: string): PasswordTips {
  const chars = [...pw];
  const lower = pw.toLowerCase();
  const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^\p{L}\p{N}]/u, /[^\x00-\x7f]/].filter((re, i) =>
    i === 4 ? chars.some((c) => /\p{L}/u.test(c) && /[^\x00-\x7f]/.test(c)) : re.test(pw),
  ).length;
  const tips: PasswordTip[] = [];
  if (chars.length < 12) tips.push('too_short');
  if (/^[0-9]+$/.test(pw)) tips.push('only_digits');
  else if (kinds < 3) tips.push('few_kinds');
  if (/(.)\1\1/u.test(pw)) tips.push('repeated');
  if (SEQUENCES.some((a) => hasRun(lower, a, 4))) tips.push('sequence');
  if (KEYBOARD.some((a) => hasRun(lower, a, 4))) tips.push('keyboard');
  if (/(19[5-9][0-9]|20[0-4][0-9])/.test(pw)) tips.push('year');
  return { length: chars.length, kinds, tips };
}
