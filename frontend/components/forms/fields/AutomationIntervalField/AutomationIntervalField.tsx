import classnames from "classnames";
import React from "react";

// @ts-ignore
import Dropdown from "components/forms/fields/Dropdown";
import FormField from "components/forms/FormField";
import {
  WEBHOOK_INTERVAL_UNIT_OPTIONS,
  WebhookIntervalUnit,
} from "utilities/webhook_interval";

const baseClass = "automation-interval-field";
const AMOUNT_FIELD_NAME = "automation-interval-amount";

export interface IAutomationIntervalFieldProps {
  /** Raw whole-number amount ("" while the user is mid-edit). */
  amount: string;
  unit: WebhookIntervalUnit;
  onAmountChange: (amount: string) => void;
  onUnitChange: (unit: WebhookIntervalUnit) => void;
  /** Runs when the amount input loses focus. */
  onBlur?: () => void;
  error?: string | null;
  disabled?: boolean;
  label?: React.ReactNode;
  tooltip?: React.ReactNode;
  helpText?: React.ReactNode;
  className?: string;
}

/**
 * A shared numeric amount + unit interval field (e.g. "24 Hours"), used
 * wherever a webhook/automation check interval is edited. Validation lives in
 * utilities/webhook_interval so callers can surface the same errors the field
 * itself reports on blur.
 */
const AutomationIntervalField = ({
  amount,
  unit,
  onAmountChange,
  onUnitChange,
  onBlur,
  error,
  disabled = false,
  label = "Check interval",
  tooltip = "How often Fleet checks whether to send automations webhooks.",
  helpText,
  className,
}: IAutomationIntervalFieldProps): JSX.Element => (
  <FormField
    className={classnames(baseClass, className)}
    type="interval"
    name={AMOUNT_FIELD_NAME}
    label={label}
    error={error}
    tooltip={tooltip}
    helpText={helpText}
    disabled={disabled}
  >
    <div className={`${baseClass}__controls`}>
      <input
        className={classnames("input-field", `${baseClass}__amount`, {
          "input-field--error": !!error,
          "input-field--disabled": disabled,
        })}
        type="number"
        step="any"
        id={AMOUNT_FIELD_NAME}
        name={AMOUNT_FIELD_NAME}
        value={amount}
        onChange={(evt) => onAmountChange(evt.target.value)}
        onBlur={onBlur}
        disabled={disabled}
        aria-label={typeof label === "string" ? label : undefined}
      />
      <Dropdown
        wrapperClassName={`${baseClass}__unit`}
        options={WEBHOOK_INTERVAL_UNIT_OPTIONS}
        value={unit}
        onChange={(value: WebhookIntervalUnit) => onUnitChange(value)}
        name={`${AMOUNT_FIELD_NAME}-unit`}
        searchable={false}
        disabled={disabled}
      />
    </div>
  </FormField>
);

export default AutomationIntervalField;
