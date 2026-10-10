import { fireEvent, screen, within } from "@testing-library/react";
import React from "react";

import { createCustomRenderer } from "test/test-utils";

import AutomationMessageEditor from "./AutomationMessageEditor";

describe("AutomationMessageEditor", () => {
  it("previews the policy name and resolution placeholders", () => {
    const render = createCustomRenderer();
    render(<AutomationMessageEditor canEdit />);

    expect(
      screen.getByText("PacketFence automation message")
    ).toBeInTheDocument();
    expect(
      screen.getAllByText(/Windows Firewall enabled on all profiles/)
    ).toHaveLength(2);
    expect(
      screen.getByText(/The policy’s configured resolution will appear here/)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Changes aren’t saved, and messages aren’t sent/)
    ).toBeInTheDocument();
  });

  it("lets global admins edit the message and updates the preview", async () => {
    const render = createCustomRenderer();
    render(<AutomationMessageEditor canEdit />);

    const titleInput = screen.getByLabelText("Message title");
    fireEvent.change(titleInput, {
      target: { value: "Policy alert for {policy_name}" },
    });

    expect(
      within(
        screen.getByText("Preview").parentElement as HTMLElement
      ).getByText("Policy alert for Windows Firewall enabled on all profiles")
    ).toBeInTheDocument();
  });

  it("keeps the editor read-only for non-admins", () => {
    const render = createCustomRenderer();
    render(<AutomationMessageEditor canEdit={false} />);

    expect(screen.getByLabelText("Message title")).toBeDisabled();
    expect(screen.getByLabelText("Additional message")).toBeDisabled();
    expect(
      screen.getByText("A global admin can edit this message.")
    ).toBeInTheDocument();
  });
});
