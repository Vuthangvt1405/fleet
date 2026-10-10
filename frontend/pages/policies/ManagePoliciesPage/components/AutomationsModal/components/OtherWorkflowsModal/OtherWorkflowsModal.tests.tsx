import { screen } from "@testing-library/react";
import React from "react";

import createMockConfig from "__mocks__/configMock";
import { IAutomationsConfig } from "interfaces/config";
import { IGlobalIntegrations } from "interfaces/integration";
import { renderWithSetup, createMockRouter } from "test/test-utils";

import { IAutomationFormHandle } from "../../types";

import OtherWorkflowsModal, {
  IOtherWorkflowsModalSubmit,
} from "./OtherWorkflowsModal";

const INVALID_URL_ERROR = "Destination URL is not a valid URL";
const REQUIRED_URL_ERROR = "Please add a destination URL";
const URL_PLACEHOLDER = "https://server.com/example";
const INTERVAL_LABEL = "Check interval";

const baseConfig = createMockConfig();

// Webhook automations enabled + empty URL so the Destination URL field renders
// and is editable.
const automationsConfig = ({
  webhook_settings: {
    ...baseConfig.webhook_settings,
    failing_policies_webhook: {
      ...baseConfig.webhook_settings.failing_policies_webhook,
      enable_failing_policies_webhook: true,
      destination_url: "",
    },
  },
  integrations: { jira: [], zendesk: [], google_calendar: null },
} as unknown) as IAutomationsConfig;

// Same as above, but with a valid URL so only the interval can fail validation.
const automationsConfigWithValidUrl = ({
  ...automationsConfig,
  webhook_settings: {
    ...automationsConfig.webhook_settings,
    failing_policies_webhook: {
      ...automationsConfig.webhook_settings.failing_policies_webhook,
      destination_url: "https://example.com/webhook",
    },
  },
} as unknown) as IAutomationsConfig;

const availableIntegrations = ({
  jira: [],
  zendesk: [],
} as unknown) as IGlobalIntegrations;

type OtherWorkflowsModalProps = React.ComponentProps<
  typeof OtherWorkflowsModal
>;

const renderModal = (props: Partial<OtherWorkflowsModalProps> = {}) => {
  const ref = React.createRef<
    IAutomationFormHandle<IOtherWorkflowsModalSubmit>
  >();
  const utils = renderWithSetup(
    <OtherWorkflowsModal
      ref={ref}
      router={createMockRouter()}
      automationsConfig={automationsConfig}
      availableIntegrations={availableIntegrations}
      {...props}
    />
  );
  return { ...utils, ref };
};

describe("OtherWorkflowsModal - Destination URL validation", () => {
  it("does not show a validation error on open", () => {
    renderModal();

    expect(screen.getByPlaceholderText(URL_PLACEHOLDER)).toBeInTheDocument();
    expect(screen.queryByText(INVALID_URL_ERROR)).not.toBeInTheDocument();
    expect(screen.queryByText(REQUIRED_URL_ERROR)).not.toBeInTheDocument();
  });

  it("shows an error when blurred with an invalid URL", async () => {
    const { user } = renderModal();

    await user.type(
      screen.getByPlaceholderText(URL_PLACEHOLDER),
      "not-a-valid-url"
    );
    await user.tab();

    expect(await screen.findByText(INVALID_URL_ERROR)).toBeInTheDocument();
  });

  it("shows a required error when blurred while empty", async () => {
    const { user } = renderModal();

    await user.click(screen.getByPlaceholderText(URL_PLACEHOLDER));
    await user.tab();

    expect(await screen.findByText(REQUIRED_URL_ERROR)).toBeInTheDocument();
  });

  it("clears the error once the user edits the field", async () => {
    const { user } = renderModal();

    const urlInput = screen.getByPlaceholderText(URL_PLACEHOLDER);
    await user.type(urlInput, "not-a-valid-url");
    await user.tab();
    expect(await screen.findByText(INVALID_URL_ERROR)).toBeInTheDocument();

    await user.type(urlInput, "a");

    expect(screen.queryByText(INVALID_URL_ERROR)).not.toBeInTheDocument();
  });

  it("shows no error when blurred with a valid URL", async () => {
    const { user } = renderModal();

    await user.type(
      screen.getByPlaceholderText(URL_PLACEHOLDER),
      "https://example.com/webhook"
    );
    await user.tab();

    expect(screen.queryByText(INVALID_URL_ERROR)).not.toBeInTheDocument();
    expect(screen.queryByText(REQUIRED_URL_ERROR)).not.toBeInTheDocument();
  });
});

describe("OtherWorkflowsModal - Check interval", () => {
  it("disables the interval and omits it from the payload in team scope", () => {
    const { ref } = renderModal();

    expect(screen.getByLabelText(INTERVAL_LABEL)).toBeDisabled();
    const data = ref.current?.getFormData();
    expect(data && "interval" in data.webhook_settings).toBe(false);
  });

  it("does not include the interval in GitOps mode", () => {
    const { ref } = renderModal({
      isGlobalScope: true,
      gitOpsModeEnabled: true,
      globalWebhookInterval: "12h0m0s",
    });

    expect(screen.getByLabelText(INTERVAL_LABEL)).toBeDisabled();
    const data = ref.current?.getFormData();
    expect(data && "interval" in data.webhook_settings).toBe(false);
  });

  it("shows the configured global interval, editable in All fleets", async () => {
    const { user, ref } = renderModal({
      isGlobalScope: true,
      globalWebhookInterval: "12h0m0s",
      automationsConfig: automationsConfigWithValidUrl,
    });

    const input = screen.getByLabelText(INTERVAL_LABEL);
    expect(input).toHaveValue(12);
    expect(input).not.toBeDisabled();

    await user.clear(input);
    await user.type(input, "5");

    expect(ref.current?.getFormData()?.webhook_settings.interval).toBe(
      "5h0m0s"
    );
  });

  it("blocks validation when the interval is empty in All fleets", async () => {
    const { user, ref } = renderModal({
      isGlobalScope: true,
      globalWebhookInterval: "12h0m0s",
      automationsConfig: automationsConfigWithValidUrl,
    });

    await user.clear(screen.getByLabelText(INTERVAL_LABEL));

    expect(ref.current?.validate()).toBe(false);
    expect(
      await screen.findByText("Interval must be present")
    ).toBeInTheDocument();
  });

  it("validates when the interval and URL are both valid", () => {
    const { ref } = renderModal({
      isGlobalScope: true,
      globalWebhookInterval: "12h0m0s",
      automationsConfig: automationsConfigWithValidUrl,
    });

    expect(ref.current?.validate()).toBe(true);
  });

  it("marks the form dirty when the interval changes in All fleets", async () => {
    const { user, ref } = renderModal({
      isGlobalScope: true,
      globalWebhookInterval: "12h0m0s",
    });

    expect(ref.current?.isDirty()).toBe(false);

    await user.clear(screen.getByLabelText(INTERVAL_LABEL));

    expect(ref.current?.isDirty()).toBe(true);
  });
});
