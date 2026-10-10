import { screen } from "@testing-library/react";
import React, { useState } from "react";

import { renderWithSetup } from "test/test-utils";
import { WebhookIntervalUnit } from "utilities/webhook_interval";

import AutomationIntervalField, {
  IAutomationIntervalFieldProps,
} from "./AutomationIntervalField";

const LABEL = "Check interval";

// The field is fully controlled, so harness it with local state to exercise
// edits the way a real form would.
const renderField = (
  overrides: Partial<IAutomationIntervalFieldProps> = {}
) => {
  const onAmountChange = jest.fn();
  const onUnitChange = jest.fn();

  const Harness = (): JSX.Element => {
    const [amount, setAmount] = useState(overrides.amount ?? "24");
    const [unit, setUnit] = useState<WebhookIntervalUnit>(
      overrides.unit ?? "h"
    );

    return (
      <AutomationIntervalField
        {...overrides}
        amount={amount}
        unit={unit}
        onAmountChange={(value) => {
          onAmountChange(value);
          setAmount(value);
        }}
        onUnitChange={(value) => {
          onUnitChange(value);
          setUnit(value);
        }}
      />
    );
  };

  const utils = renderWithSetup(<Harness />);
  return { ...utils, onAmountChange, onUnitChange };
};

describe("AutomationIntervalField", () => {
  it("renders the amount and unit", () => {
    renderField();

    expect(screen.getByLabelText(LABEL)).toHaveValue(24);
    expect(screen.getByText("Hours")).toBeInTheDocument();
  });

  it("renders an initial unit other than hours", () => {
    renderField({ amount: "3", unit: "d" });

    expect(screen.getByLabelText(LABEL)).toHaveValue(3);
    expect(screen.getByText("Days")).toBeInTheDocument();
  });

  it("calls onAmountChange as the amount is edited", async () => {
    const { user, onAmountChange } = renderField();

    const input = screen.getByLabelText(LABEL);
    await user.clear(input);
    await user.type(input, "30");

    expect(onAmountChange).toHaveBeenLastCalledWith("30");
  });

  it("calls onUnitChange when the unit is changed", async () => {
    const { user, onUnitChange } = renderField();

    await user.click(screen.getByText("Hours"));
    await user.click(screen.getByText("Days"));

    expect(onUnitChange).toHaveBeenLastCalledWith("d");
  });

  it("calls onBlur when the amount loses focus", async () => {
    const onBlur = jest.fn();
    const { user } = renderField({ onBlur });

    await user.click(screen.getByLabelText(LABEL));
    await user.tab();

    expect(onBlur).toHaveBeenCalled();
  });

  it("replaces the label with the error message", () => {
    renderField({ error: "Interval must be at least 1 minute" });

    expect(
      screen.getByText("Interval must be at least 1 minute")
    ).toBeInTheDocument();
    expect(screen.queryByText(LABEL)).not.toBeInTheDocument();
    // The input keeps a stable accessible name so it remains findable while
    // the visible label is showing the error.
    expect(screen.getByLabelText(LABEL)).toBeInTheDocument();
  });

  it("disables the controls when disabled", () => {
    renderField({ disabled: true });

    expect(screen.getByLabelText(LABEL)).toBeDisabled();
  });
});
