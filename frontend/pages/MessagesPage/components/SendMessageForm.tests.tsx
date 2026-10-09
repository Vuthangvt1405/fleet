import { screen, waitFor } from "@testing-library/react";
import React from "react";

import createMockHost from "__mocks__/hostMock";
import hostsAPI from "services/entities/hosts";
import { createCustomRenderer } from "test/test-utils";

import SendMessageForm from "./SendMessageForm";

jest.mock("services/entities/hosts");

describe("SendMessageForm", () => {
  it("searches for hosts, adds chips, and submits all selected host IDs", async () => {
    const hosts = [
      createMockHost({ id: 42, hostname: "WKS-0042" }),
      createMockHost({ id: 43, hostname: "WKS-0043" }),
    ];
    jest.mocked(hostsAPI.loadHosts).mockResolvedValue({ hosts } as never);
    const onSend = jest.fn().mockResolvedValue([]);
    const render = createCustomRenderer();
    const { user } = render(
      <SendMessageForm isSending={false} onSend={onSend} />
    );

    await waitFor(() => expect(hostsAPI.loadHosts).toHaveBeenCalled());
    await user.click(screen.getByRole("combobox", { name: "Select hosts" }));
    await user.click(await screen.findByText("WKS-0042"));
    await user.click(screen.getByRole("combobox", { name: "Select hosts" }));
    await user.click(await screen.findByText("WKS-0043"));

    await user.type(screen.getByLabelText("Title"), "Maintenance notice");
    await user.type(
      screen.getByLabelText("Body"),
      "Restart your device tonight."
    );
    await user.click(screen.getByRole("button", { name: "Send message" }));

    await waitFor(() =>
      expect(onSend).toHaveBeenCalledWith({
        host_ids: [42, 43],
        title: "Maintenance notice",
        body: "Restart your device tonight.",
      })
    );
  });

  it("keeps only failed hosts selected after a partial send", async () => {
    const hosts = [
      createMockHost({ id: 42, hostname: "WKS-0042" }),
      createMockHost({ id: 43, hostname: "WKS-0043" }),
    ];
    jest.mocked(hostsAPI.loadHosts).mockResolvedValue({ hosts } as never);
    const onSend = jest.fn().mockResolvedValue([43]);
    const render = createCustomRenderer();
    const { user } = render(
      <SendMessageForm isSending={false} onSend={onSend} />
    );

    await waitFor(() => expect(hostsAPI.loadHosts).toHaveBeenCalled());
    await user.click(screen.getByRole("combobox", { name: "Select hosts" }));
    await user.click(await screen.findByText("WKS-0042"));
    await user.click(screen.getByRole("combobox", { name: "Select hosts" }));
    await user.click(await screen.findByText("WKS-0043"));
    await user.type(screen.getByLabelText("Title"), "Maintenance notice");
    await user.type(
      screen.getByLabelText("Body"),
      "Restart your device tonight."
    );
    await user.click(screen.getByRole("button", { name: "Send message" }));

    await waitFor(() =>
      expect(screen.getByText("WKS-0043")).toBeInTheDocument()
    );
    expect(screen.queryByText("WKS-0042")).not.toBeInTheDocument();
  });
});
