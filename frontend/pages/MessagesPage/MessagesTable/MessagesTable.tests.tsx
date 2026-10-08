import { screen } from "@testing-library/react";
import React from "react";

import { createMockMessage } from "__mocks__/messagesMock";
import { createCustomRenderer } from "test/test-utils";

import MessagesTable from "./MessagesTable";

describe("MessagesTable", () => {
  it("Renders empty state when no messages are provided", () => {
    const render = createCustomRenderer();
    render(<MessagesTable messages={[]} />);

    expect(screen.getByText("No messages sent")).toBeInTheDocument();
    expect(
      screen.getByText("Messages you send to hosts will appear here.")
    ).toBeInTheDocument();
  });

  it("Renders message history rows", () => {
    const messages = [
      createMockMessage({
        id: 1,
        hostname: "WKS-0142",
        user_email: "ana@acme.com",
        title: "Blocked app detected",
        status: "sent",
      }),
      createMockMessage({
        id: 2,
        hostname: "WKS-0891",
        title: "Critical CVE warning",
        status: "queued",
      }),
    ];

    const render = createCustomRenderer();
    render(<MessagesTable messages={messages} />);

    expect(screen.getByText("Sent at")).toBeInTheDocument();
    expect(screen.getByText("To")).toBeInTheDocument();
    expect(screen.getByText("Title")).toBeInTheDocument();
    expect(screen.getByText("Status")).toBeInTheDocument();
    // TooltipTruncatedTextCell renders the value twice (cell + tooltip),
    // same as the LabelsTable tests.
    expect(screen.queryAllByText("Blocked app detected")).toHaveLength(2);
    expect(screen.queryAllByText("Critical CVE warning")).toHaveLength(2);
  });
});
