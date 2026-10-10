import { screen } from "@testing-library/react";
import React from "react";

import createMockConfig from "__mocks__/configMock";
import { renderWithSetup, createMockRouter } from "test/test-utils";

import GlobalHostStatusWebhook from "./GlobalHostStatusWebhook";

const REQUIRED_URL_ERROR = "Destination URL must be present";
const INVALID_URL_ERROR = "Destination URL is not a valid URL";
const URL_PLACEHOLDER = "https://server.com/example";
const ENABLE_LABEL = "Enable host status webhook";
const INTERVAL_LABEL = "Check interval";

const baseConfig = createMockConfig();

// The webhook starts disabled with an empty URL so we can exercise enabling it.
const disabledWebhookConfig = {
  ...baseConfig,
  webhook_settings: {
    ...baseConfig.webhook_settings,
    host_status_webhook: {
      enable_host_status_webhook: false,
      destination_url: "",
      host_percentage: 1,
      days_count: 1,
    },
  },
};

const renderCard = (handleSubmit = jest.fn()) => {
  const utils = renderWithSetup(
    <GlobalHostStatusWebhook
      appConfig={disabledWebhookConfig}
      handleSubmit={handleSubmit}
      isUpdatingSettings={false}
      router={createMockRouter()}
    />
  );
  return { ...utils, handleSubmit };
};

describe("GlobalHostStatusWebhook - Destination URL validation", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("does not show an error when the webhook is first enabled (#40410)", async () => {
    const { user } = renderCard();

    await user.click(screen.getByText(ENABLE_LABEL));

    expect(screen.getByPlaceholderText(URL_PLACEHOLDER)).toBeInTheDocument();
    expect(screen.queryByText(REQUIRED_URL_ERROR)).not.toBeInTheDocument();
    expect(screen.queryByText(INVALID_URL_ERROR)).not.toBeInTheDocument();
  });

  it("shows an error when the URL field is blurred while empty", async () => {
    const { user } = renderCard();

    await user.click(screen.getByText(ENABLE_LABEL));
    await user.click(screen.getByPlaceholderText(URL_PLACEHOLDER));
    await user.tab();

    expect(await screen.findByText(REQUIRED_URL_ERROR)).toBeInTheDocument();
  });

  it("shows an error when the URL field is blurred with an invalid URL", async () => {
    const { user } = renderCard();

    await user.click(screen.getByText(ENABLE_LABEL));
    await user.type(screen.getByPlaceholderText(URL_PLACEHOLDER), "not-a-url");
    await user.tab();

    expect(await screen.findByText(INVALID_URL_ERROR)).toBeInTheDocument();
  });

  it("clears the error once a URL is entered", async () => {
    const { user } = renderCard();

    await user.click(screen.getByText(ENABLE_LABEL));
    const urlInput = screen.getByPlaceholderText(URL_PLACEHOLDER);
    await user.click(urlInput);
    await user.tab();
    expect(await screen.findByText(REQUIRED_URL_ERROR)).toBeInTheDocument();

    await user.type(urlInput, "https://example.com");

    expect(screen.queryByText(REQUIRED_URL_ERROR)).not.toBeInTheDocument();
  });

  it("blocks submit and shows an error when the URL is empty", async () => {
    const { user, handleSubmit } = renderCard();

    await user.click(screen.getByText(ENABLE_LABEL));
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText(REQUIRED_URL_ERROR)).toBeInTheDocument();
    expect(handleSubmit).not.toHaveBeenCalled();
  });

  it("submits when the URL is valid", async () => {
    const { user, handleSubmit } = renderCard();

    await user.click(screen.getByText(ENABLE_LABEL));
    await user.type(
      screen.getByPlaceholderText(URL_PLACEHOLDER),
      "https://example.com"
    );
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(handleSubmit).toHaveBeenCalled();
  });
});

describe("GlobalHostStatusWebhook - Check interval", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("shows the configured interval", () => {
    renderCard();

    // configMock stores "24h0m0s", which renders as 1 Day
    expect(screen.getByLabelText(INTERVAL_LABEL)).toHaveValue(1);
    expect(screen.getByText("Days")).toBeInTheDocument();
  });

  it("shows an error when the amount is cleared and blurred", async () => {
    const { user } = renderCard();

    await user.clear(screen.getByLabelText(INTERVAL_LABEL));
    await user.tab();

    expect(
      await screen.findByText("Interval must be present")
    ).toBeInTheDocument();
  });

  it("blocks submit when the interval is invalid", async () => {
    const { user, handleSubmit } = renderCard();

    await user.clear(screen.getByLabelText(INTERVAL_LABEL));
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(
      await screen.findByText("Interval must be present")
    ).toBeInTheDocument();
    expect(handleSubmit).not.toHaveBeenCalled();
  });

  it("blocks submit when the interval is above 7 days", async () => {
    const { user, handleSubmit } = renderCard();

    const input = screen.getByLabelText(INTERVAL_LABEL);
    await user.clear(input);
    await user.type(input, "10081");

    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(
      await screen.findByText("Interval must be 7 days or less")
    ).toBeInTheDocument();
    expect(handleSubmit).not.toHaveBeenCalled();
  });

  it("submits the interval formatted as a Go duration", async () => {
    const { user, handleSubmit } = renderCard();

    // Switch the unit from Days to Hours, then set 12
    await user.click(screen.getByText("Days"));
    await user.click(screen.getByText("Hours"));

    const input = screen.getByLabelText(INTERVAL_LABEL);
    await user.clear(input);
    await user.type(input, "12");

    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(handleSubmit).toHaveBeenCalled();
    expect(handleSubmit.mock.calls[0][0].webhook_settings.interval).toBe(
      "12h0m0s"
    );
  });
});
