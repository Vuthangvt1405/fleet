export const SAMPLE_POLICY_NAME = "Windows Firewall enabled on all profiles";
export const SAMPLE_POLICY_RESOLUTION =
  "The policy’s configured resolution will appear here.";
export const DEFAULT_AUTOMATION_TITLE = "Action needed: {policy_name}";

export const buildAutomationPreviewTitle = (title: string): string =>
  title.replaceAll("{policy_name}", SAMPLE_POLICY_NAME);

const buildReasonMessage = (): string =>
  `This device failed the “${SAMPLE_POLICY_NAME}” policy.\n\nTo resolve this, ${SAMPLE_POLICY_RESOLUTION}`;

export const buildAutomationPreviewBody = (additionalMessage: string): string =>
  [buildReasonMessage(), additionalMessage.trim()].filter(Boolean).join("\n\n");
