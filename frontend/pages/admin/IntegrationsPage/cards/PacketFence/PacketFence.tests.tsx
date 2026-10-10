import { screen, waitFor } from "@testing-library/react";
import React from "react";

import createMockConfig from "__mocks__/configMock";
import createMockLicense from "__mocks__/licenseMock";
import { IAppConfigFormProps } from "pages/admin/OrgSettingsPage/cards/constants";
import configAPI from "services/entities/config";
import packetfenceAPI from "services/entities/packetfence";
import { createCustomRenderer, createMockRouter } from "test/test-utils";

import PacketFence from "./PacketFence";

jest.mock("services/entities/config");
jest.mock("services/entities/packetfence");
jest.mock("components/ToastNotification", () => ({
  notify: {
    success: jest.fn(),
    error: jest.fn(),
    batch: jest.fn(),
    dismiss: jest.fn(),
  },
}));

const defaultProps: IAppConfigFormProps = {
  appConfig: createMockConfig({
    license: createMockLicense({ tier: "free" }),
  }),
  handleSubmit: jest.fn() as IAppConfigFormProps["handleSubmit"],
  router: createMockRouter(),
};

const savedConfigProps: IAppConfigFormProps = {
  ...defaultProps,
  appConfig: createMockConfig({
    license: createMockLicense({ tier: "free" }),
    integrations: {
      ...createMockConfig().integrations,
      packetfence: {
        base_url: "https://packetfence.example.com",
        username: "fleet-revocation-service",
        password: "********",
        enabled: false,
        managed_event_types: ["3500001", "3500002"],
        require_exclusive_ownership: true,
        policy_checks_required: 2,
        cve_checks_required: 1,
        dry_run: true,
      },
    },
  }),
};

describe("PacketFence", () => {
  const render = createCustomRenderer({
    withBackendMock: true,
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it("renders the section heading and connection fields", () => {
    render(<PacketFence {...defaultProps} />);
    expect(screen.getByText("PacketFence")).toBeInTheDocument();
    expect(screen.getByLabelText(/packetfence url/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /test connection/i })
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /save/i })).toBeInTheDocument();
  });

  it("renders the form on free tier (no premium gate)", () => {
    render(
      <PacketFence
        {...defaultProps}
        appConfig={createMockConfig({
          license: createMockLicense({ tier: "free" }),
        })}
      />
    );
    expect(screen.getByLabelText(/packetfence url/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /test connection/i })
    ).toBeInTheDocument();
  });

  it("populates fields from appConfig prop with masked password", () => {
    render(<PacketFence {...savedConfigProps} />);
    expect(screen.getByLabelText(/packetfence url/i)).toHaveValue(
      "https://packetfence.example.com"
    );
    expect(screen.getByLabelText(/username/i)).toHaveValue(
      "fleet-revocation-service"
    );
    expect(screen.getByLabelText(/password/i)).toHaveValue("********");
  });

  it("shows an error for non-https URLs", async () => {
    const { user } = render(<PacketFence {...defaultProps} />);
    await user.type(
      screen.getByLabelText(/packetfence url/i),
      "http://packetfence.example.com"
    );
    await user.tab();
    await waitFor(() => {
      expect(
        screen.getByText(/must be an absolute https url/i)
      ).toBeInTheDocument();
    });
  });

  it("opens a confirmation modal when turning automatic clearing on", async () => {
    const { user } = render(<PacketFence {...savedConfigProps} />);
    await user.click(
      screen.getByRole("switch", {
        name: /automatic packetfence event clearing/i,
      })
    );
    expect(
      await screen.findByText(/turn on automatic event clearing/i)
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^turn on$/i }));
    expect(
      screen.getByText(/automatic event clearing is on/i)
    ).toBeInTheDocument();
    // Safety settings are revealed once enabled.
    expect(
      screen.getByLabelText(/managed security event types/i)
    ).toBeInTheDocument();
  });

  it("omits an unchanged masked password on save", async () => {
    const { user } = render(<PacketFence {...savedConfigProps} />);
    await user.click(screen.getByRole("button", { name: /save/i }));
    await waitFor(() => {
      expect(configAPI.update).toHaveBeenCalledWith({
        integrations: {
          packetfence: {
            base_url: "https://packetfence.example.com",
            username: "fleet-revocation-service",
            enabled: false,
            managed_event_types: ["3500001", "3500002"],
            require_exclusive_ownership: true,
            policy_checks_required: 2,
            cve_checks_required: 1,
            dry_run: true,
          },
        },
      });
    });
    const payload = (configAPI.update as jest.Mock).mock.calls[0][0];
    expect(payload.integrations.packetfence).not.toHaveProperty("password");
  });

  it("tests the connection and shows success", async () => {
    (packetfenceAPI.testConnection as jest.Mock).mockResolvedValue({
      connected: true,
      message: "Successfully connected to PacketFence.",
    });
    const { user } = render(<PacketFence {...savedConfigProps} />);
    await user.click(screen.getByRole("button", { name: /test connection/i }));
    await waitFor(() => {
      expect(packetfenceAPI.testConnection).toHaveBeenCalledWith({
        base_url: "https://packetfence.example.com",
        username: "fleet-revocation-service",
        password: "********",
      });
    });
    expect(
      await screen.findByText(/successfully connected to packetfence/i)
    ).toBeInTheDocument();
  });
});
