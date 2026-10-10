import { fireEvent, screen, within } from "@testing-library/react";
import React from "react";

import { createCustomRenderer } from "test/test-utils";

import AutomationMessageEditor from "./AutomationMessageEditor";

const renderEditor = (
  canEdit: boolean,
  onSave = jest.fn().mockResolvedValue(true)
) => {
  const render = createCustomRenderer();
  const rendered = render(
    <AutomationMessageEditor
      canEdit={canEdit}
      enabled={false}
      isSaving={false}
      onSave={onSave}
    />
  );
  return { ...rendered, onSave };
};

describe("AutomationMessageEditor", () => {
  it("renders the current message preview and an edit button", () => {
    renderEditor(true);

    expect(
      screen.getByText("PacketFence automation message")
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Action needed: Windows Firewall enabled on all profiles"
      )
    ).toBeInTheDocument();
    expect(
      screen.getByText(/To resolve this, The policy’s configured resolution/)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Messages are sent only when a policy webhook/)
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Edit message" })
    ).toBeInTheDocument();
  });

  it("opens the modal and saves edits to the card preview", async () => {
    const { user, onSave } = renderEditor(true);

    await user.click(screen.getByRole("button", { name: "Edit message" }));

    expect(
      screen.getByText("Edit PacketFence automation message")
    ).toBeInTheDocument();

    const titleInput = screen.getByLabelText("Message title");
    fireEvent.change(titleInput, {
      target: { value: "Policy alert for {policy_name}" },
    });

    const modalRoot = screen
      .getByText("Edit PacketFence automation message")
      .closest(".automation-message-modal") as HTMLElement;
    expect(
      within(modalRoot).getByText(
        "Policy alert for Windows Firewall enabled on all profiles"
      )
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(onSave).toHaveBeenCalledWith({
      enabled: false,
      title: "Policy alert for {policy_name}",
      additionalMessage: "",
    });

    expect(
      screen.queryByText("Edit PacketFence automation message")
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(
        "Policy alert for Windows Firewall enabled on all profiles"
      )
    ).toBeInTheDocument();
  });

  it("discards modal edits on cancel", async () => {
    const { user } = renderEditor(true);

    await user.click(screen.getByRole("button", { name: "Edit message" }));

    const titleInput = screen.getByLabelText("Message title");
    fireEvent.change(titleInput, {
      target: { value: "Discarded title {policy_name}" },
    });
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(
      screen.queryByText("Edit PacketFence automation message")
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(
        "Action needed: Windows Firewall enabled on all profiles"
      )
    ).toBeInTheDocument();
  });

  it("hides the edit button for non-admins", () => {
    renderEditor(false);

    expect(
      screen.queryByRole("button", { name: "Edit message" })
    ).not.toBeInTheDocument();
    expect(
      screen.getByText("A global admin can edit this message.")
    ).toBeInTheDocument();
  });
});
