import {
  formatWebhookInterval,
  parseWebhookInterval,
  validateWebhookInterval,
} from "./webhook_interval";

describe("parseWebhookInterval", () => {
  it("parses the canonical form the backend echoes (Go Duration.String)", () => {
    expect(parseWebhookInterval("24h0m0s")).toEqual({ amount: 1, unit: "d" });
    expect(parseWebhookInterval("12h0m0s")).toEqual({ amount: 12, unit: "h" });
    expect(parseWebhookInterval("1m0s")).toEqual({ amount: 1, unit: "m" });
    expect(parseWebhookInterval("1h30m0s")).toEqual({ amount: 90, unit: "m" });
  });

  it("parses short Go duration forms", () => {
    expect(parseWebhookInterval("12h")).toEqual({ amount: 12, unit: "h" });
    expect(parseWebhookInterval("48h")).toEqual({ amount: 2, unit: "d" });
    expect(parseWebhookInterval("90m")).toEqual({ amount: 90, unit: "m" });
    expect(parseWebhookInterval("60s")).toEqual({ amount: 1, unit: "m" });
  });

  it("keeps sub-minute values in minutes", () => {
    expect(parseWebhookInterval("30s")).toEqual({ amount: 0.5, unit: "m" });
  });

  it("returns null for missing, zero, or malformed values", () => {
    expect(parseWebhookInterval(undefined)).toBeNull();
    expect(parseWebhookInterval(null)).toBeNull();
    expect(parseWebhookInterval("")).toBeNull();
    expect(parseWebhookInterval("0s")).toBeNull();
    expect(parseWebhookInterval("-5m")).toBeNull();
    expect(parseWebhookInterval("not-a-duration")).toBeNull();
  });
});

describe("formatWebhookInterval", () => {
  it("formats to the canonical Go duration form the backend echoes", () => {
    expect(formatWebhookInterval(24, "h")).toBe("24h0m0s");
    expect(formatWebhookInterval(1, "d")).toBe("24h0m0s");
    expect(formatWebhookInterval(1, "m")).toBe("1m0s");
    expect(formatWebhookInterval(90, "m")).toBe("1h30m0s");
    expect(formatWebhookInterval(7, "d")).toBe("168h0m0s");
  });

  it("accepts the string amounts held in form state", () => {
    expect(formatWebhookInterval("12", "h")).toBe("12h0m0s");
    expect(formatWebhookInterval("5", "d")).toBe("120h0m0s");
  });

  it("round-trips through parseWebhookInterval", () => {
    expect(parseWebhookInterval(formatWebhookInterval(12, "h"))).toEqual({
      amount: 12,
      unit: "h",
    });
    expect(parseWebhookInterval(formatWebhookInterval(3, "d"))).toEqual({
      amount: 3,
      unit: "d",
    });
  });

  it("returns an empty string for empty or invalid amounts", () => {
    expect(formatWebhookInterval("", "h")).toBe("");
    expect(formatWebhookInterval("abc", "h")).toBe("");
    expect(formatWebhookInterval(0, "h")).toBe("");
  });
});

describe("validateWebhookInterval", () => {
  it("accepts values from 1 minute to 7 days", () => {
    expect(validateWebhookInterval("1", "m")).toBeUndefined();
    expect(validateWebhookInterval("24", "h")).toBeUndefined();
    expect(validateWebhookInterval("7", "d")).toBeUndefined();
    // 7 days expressed in minutes is the exact upper bound
    expect(validateWebhookInterval("10080", "m")).toBeUndefined();
    expect(validateWebhookInterval("168", "h")).toBeUndefined();
  });

  it("requires a value", () => {
    expect(validateWebhookInterval("", "h")).toBe("Interval must be present");
    expect(validateWebhookInterval("   ", "m")).toBe(
      "Interval must be present"
    );
  });

  it("requires a whole number", () => {
    expect(validateWebhookInterval("1.5", "m")).toBe(
      "Interval must be a whole number"
    );
    expect(validateWebhookInterval("abc", "m")).toBe(
      "Interval must be a whole number"
    );
  });

  it("rejects intervals below one minute", () => {
    expect(validateWebhookInterval("0", "m")).toBe(
      "Interval must be at least 1 minute"
    );
  });

  it("rejects intervals above seven days", () => {
    expect(validateWebhookInterval("8", "d")).toBe(
      "Interval must be 7 days or less"
    );
    expect(validateWebhookInterval("169", "h")).toBe(
      "Interval must be 7 days or less"
    );
    expect(validateWebhookInterval("10081", "m")).toBe(
      "Interval must be 7 days or less"
    );
  });
});
