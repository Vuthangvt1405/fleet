import { IDropdownOption } from "interfaces/dropdownOption";

/**
 * Unit the webhook interval amount is entered in. `d` (days) is a UI-only
 * unit — Go's time.ParseDuration has no day unit, so days are converted to
 * hours when formatted for the API.
 */
export type WebhookIntervalUnit = "m" | "h" | "d";

export interface IWebhookInterval {
  amount: number;
  unit: WebhookIntervalUnit;
}

const UNIT_SECONDS: Record<WebhookIntervalUnit, number> = {
  m: 60,
  h: 3600,
  d: 86400,
};

// Sub-second units are only parsed (never displayed) so values written as
// e.g. "1500ms" by hand in GitOps YAML don't render as a blank field.
const TIME_UNIT_SECONDS: Record<string, number> = {
  ns: 1e-9,
  us: 1e-6,
  µs: 1e-6,
  μs: 1e-6,
  ms: 1e-3,
  s: 1,
  m: 60,
  h: 3600,
};

const GO_DURATION_RE = /^(?:\d+(?:\.\d+)?(?:ns|us|µs|μs|ms|s|m|h))+$/;
const GO_DURATION_PART_RE = /(\d+(?:\.\d+)?)(ns|us|µs|μs|ms|s|m|h)/g;

/** The UI contract for webhook intervals. The backend accepts any duration
 *  (its schedule only floors the interval to 1s), so these bounds are
 *  enforced here: at least every minute, at most once every 7 days. */
export const MIN_WEBHOOK_INTERVAL_SECONDS = 60;
export const MAX_WEBHOOK_INTERVAL_SECONDS = 7 * 24 * 60 * 60;

export const DEFAULT_WEBHOOK_INTERVAL: IWebhookInterval = {
  amount: 24,
  unit: "h",
};

export const WEBHOOK_INTERVAL_UNIT_OPTIONS: IDropdownOption[] = [
  { label: "Minutes", value: "m" },
  { label: "Hours", value: "h" },
  { label: "Days", value: "d" },
];

/** Parses a Go duration string ("24h0m0s", "12h", "90m") into total seconds.
 *  Returns null when the value is missing, malformed, or zero. */
const parseDurationToSeconds = (value?: string | null): number | null => {
  if (!value) {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed || !GO_DURATION_RE.test(trimmed)) {
    return null;
  }
  let totalSeconds = 0;
  GO_DURATION_PART_RE.lastIndex = 0;
  let part = GO_DURATION_PART_RE.exec(trimmed);
  while (part !== null) {
    totalSeconds += parseFloat(part[1]) * TIME_UNIT_SECONDS[part[2]];
    part = GO_DURATION_PART_RE.exec(trimmed);
  }
  return totalSeconds;
};

/**
 * Parses a stored webhook interval (a Go duration string such as "24h0m0s")
 * into an amount and unit for display, preferring the largest whole unit.
 * Returns null when the value is missing or malformed — callers fall back to
 * DEFAULT_WEBHOOK_INTERVAL.
 */
export const parseWebhookInterval = (
  value?: string | null
): IWebhookInterval | null => {
  const totalSeconds = parseDurationToSeconds(value);
  if (totalSeconds === null || totalSeconds <= 0) {
    return null;
  }
  if (totalSeconds % UNIT_SECONDS.d === 0) {
    return { amount: totalSeconds / UNIT_SECONDS.d, unit: "d" };
  }
  if (totalSeconds % UNIT_SECONDS.h === 0) {
    return { amount: totalSeconds / UNIT_SECONDS.h, unit: "h" };
  }
  return { amount: totalSeconds / UNIT_SECONDS.m, unit: "m" };
};

/**
 * Formats an amount and unit back into a Go duration string in the same
 * canonical form the backend echoes ("1m0s", "12h0m0s", "1h30m0s"), so an
 * unchanged interval diffs clean against the stored config. Returns "" when
 * the amount isn't a positive number.
 */
export const formatWebhookInterval = (
  amount: string | number,
  unit: WebhookIntervalUnit
): string => {
  const numericAmount =
    typeof amount === "number" ? amount : parseFloat(amount.trim());
  if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
    return "";
  }

  const totalSeconds = numericAmount * UNIT_SECONDS[unit];
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  let formatted = "";
  if (hours !== 0) {
    formatted += `${hours}h`;
  }
  if (hours !== 0 || minutes !== 0) {
    formatted += `${minutes}m`;
  }
  formatted += `${seconds}s`;
  return formatted;
};

/**
 * Validates a raw amount and unit. Returns an error message, or undefined
 * when valid.
 */
export const validateWebhookInterval = (
  amount: string,
  unit: WebhookIntervalUnit
): string | undefined => {
  const trimmed = amount.trim();
  if (trimmed === "") {
    return "Interval must be present";
  }

  const numericAmount = Number(trimmed);
  if (!Number.isFinite(numericAmount) || !Number.isInteger(numericAmount)) {
    return "Interval must be a whole number";
  }

  const totalSeconds = numericAmount * UNIT_SECONDS[unit];
  if (totalSeconds < MIN_WEBHOOK_INTERVAL_SECONDS) {
    return "Interval must be at least 1 minute";
  }
  if (totalSeconds > MAX_WEBHOOK_INTERVAL_SECONDS) {
    return "Interval must be 7 days or less";
  }
  return undefined;
};
