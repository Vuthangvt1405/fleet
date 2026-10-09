import React, { useEffect, useState } from "react";
import { useQueryClient } from "react-query";

import Button from "components/buttons/Button";
import Checkbox from "components/forms/fields/Checkbox";
import InputField from "components/forms/fields/InputField";
import Slider from "components/forms/fields/Slider";
import validUrl from "components/forms/validators/valid_url";
import GitOpsModeTooltipWrapper from "components/GitOpsModeTooltipWrapper";
import PageDescription from "components/PageDescription";
import PremiumFeatureMessage from "components/PremiumFeatureMessage/PremiumFeatureMessage";
import SectionHeader from "components/SectionHeader";
import { notify } from "components/ToastNotification";
import TooltipWrapper from "components/TooltipWrapper";
import { getErrorReason } from "interfaces/errors";
import { IInputFieldParseTarget } from "interfaces/form_field";
import { IPacketFenceIntegration } from "interfaces/integration";
import SettingsSection from "pages/admin/components/SettingsSection";
import configAPI from "services/entities/config";
import packetfenceAPI from "services/entities/packetfence";
import { UNCHANGED_PASSWORD_API_RESPONSE } from "utilities/constants";
import { isPremiumTier } from "utilities/permissions/permissions";

import { IAppConfigFormProps } from "../../../OrgSettingsPage/cards/constants";

import EnableAutoClearModal from "./components/EnableAutoClearModal";

const baseClass = "packetfence-integration";

interface IPacketFenceFormData {
  baseUrl: string;
  username: string;
  password: string;
  passwordUnchanged: boolean;
  enabled: boolean;
  managedEventTypes: string;
  policyChecks: string;
  cveChecks: string;
  dryRun: boolean;
}

interface IPacketFenceFormErrors {
  baseUrl?: string | null;
  username?: string | null;
  password?: string | null;
  managedEventTypes?: string | null;
  policyChecks?: string | null;
  cveChecks?: string | null;
}

type IConnectionStatus =
  | { state: "untested" }
  | { state: "testing" }
  | { state: "success"; message: string }
  | { state: "error"; message: string };

const emptyFormData: IPacketFenceFormData = {
  baseUrl: "",
  username: "",
  password: "",
  passwordUnchanged: false,
  enabled: false,
  managedEventTypes: "",
  policyChecks: "2",
  cveChecks: "1",
  dryRun: true,
};

const toFormData = (
  pf?: IPacketFenceIntegration | null
): IPacketFenceFormData => {
  if (!pf) {
    return { ...emptyFormData };
  }
  const passwordUnchanged = pf.password === UNCHANGED_PASSWORD_API_RESPONSE;
  return {
    baseUrl: pf.base_url ?? "",
    username: pf.username ?? "",
    password: passwordUnchanged ? UNCHANGED_PASSWORD_API_RESPONSE : pf.password,
    passwordUnchanged,
    enabled: pf.enabled ?? false,
    managedEventTypes: (pf.managed_event_types ?? []).join(", "),
    policyChecks: String(pf.policy_checks_required ?? 2),
    cveChecks: String(pf.cve_checks_required ?? 1),
    dryRun: pf.dry_run ?? true,
  };
};

const parseEventTypes = (raw: string): string[] =>
  raw
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t !== "");

const validate = (formData: IPacketFenceFormData): IPacketFenceFormErrors => {
  const errs: IPacketFenceFormErrors = {};
  if (!formData.baseUrl) {
    errs.baseUrl = "PacketFence URL is required";
  } else if (!validUrl({ url: formData.baseUrl, protocols: ["https"] })) {
    errs.baseUrl = "PacketFence URL must be an absolute https URL";
  }
  if (!formData.username.trim()) {
    errs.username = "Username is required";
  }
  if (!formData.password) {
    errs.password = "Password is required";
  }
  const types = parseEventTypes(formData.managedEventTypes);
  if (formData.enabled && types.length === 0) {
    errs.managedEventTypes =
      "At least one managed event type is required when automatic clearing is on";
  } else if (types.some((t) => !/^\d+$/.test(t))) {
    errs.managedEventTypes = "Event types must be numeric IDs";
  }
  const policyChecks = Number(formData.policyChecks);
  if (!Number.isInteger(policyChecks) || policyChecks < 2) {
    errs.policyChecks = "Must be an integer of 2 or more";
  }
  const cveChecks = Number(formData.cveChecks);
  if (!Number.isInteger(cveChecks) || cveChecks < 1) {
    errs.cveChecks = "Must be an integer of 1 or more";
  }
  return errs;
};

const PacketFence = ({ appConfig }: IAppConfigFormProps): JSX.Element => {
  const queryClient = useQueryClient();

  const [formData, setFormData] = useState<IPacketFenceFormData>(() =>
    toFormData(appConfig.integrations.packetfence)
  );
  const [formErrors, setFormErrors] = useState<IPacketFenceFormErrors>({});
  const [isUpdating, setIsUpdating] = useState(false);
  const [connection, setConnection] = useState<IConnectionStatus>({
    state: "untested",
  });
  const [showEnableModal, setShowEnableModal] = useState(false);

  // Sync form state from config prop passed by IntegrationsPage.
  useEffect(() => {
    setFormData(toFormData(appConfig.integrations.packetfence));
    setConnection({ state: "untested" });
  }, [appConfig]);

  if (!isPremiumTier(appConfig)) {
    return (
      <SettingsSection title="PacketFence">
        <PremiumFeatureMessage />
      </SettingsSection>
    );
  }

  const gomEnabled = appConfig.gitops.gitops_mode_enabled;

  const onInputChange = ({ name, value }: IInputFieldParseTarget) => {
    const newFormData = { ...formData, [name]: value };
    if (name === "password") {
      newFormData.passwordUnchanged = value === UNCHANGED_PASSWORD_API_RESPONSE;
    }
    setFormData(newFormData);
    setFormErrors(validate(newFormData));
    if (name === "baseUrl" || name === "username" || name === "password") {
      setConnection({ state: "untested" });
    }
  };

  const onToggleEnabled = () => {
    if (!formData.enabled) {
      // Turning on requires acknowledging the safety behavior.
      setShowEnableModal(true);
      return;
    }
    setFormData({ ...formData, enabled: false });
  };

  const onConfirmEnable = () => {
    setShowEnableModal(false);
    const newFormData = { ...formData, enabled: true };
    setFormData(newFormData);
    setFormErrors(validate(newFormData));
  };

  const onTestConnection = async () => {
    const errs = validate(formData);
    setFormErrors(errs);
    if (errs.baseUrl || errs.username || errs.password) {
      return;
    }
    setConnection({ state: "testing" });
    try {
      const res = await packetfenceAPI.testConnection({
        base_url: formData.baseUrl,
        username: formData.username.trim(),
        password: formData.password,
      });
      if (res.connected) {
        setConnection({
          state: "success",
          message: res.message ?? "Successfully connected to PacketFence.",
        });
      } else {
        setConnection({
          state: "error",
          message: res.message ?? "Could not connect to PacketFence.",
        });
      }
    } catch (e) {
      setConnection({
        state: "error",
        message: getErrorReason(e) || "Could not connect to PacketFence.",
      });
    }
  };

  const onFormSubmit = async (evt: React.FormEvent<HTMLFormElement>) => {
    evt.preventDefault();
    const errs = validate(formData);
    setFormErrors(errs);
    if (Object.keys(errs).length > 0) {
      return;
    }
    setIsUpdating(true);
    try {
      // Omit an unchanged (masked) password so the backend preserves it.
      await configAPI.update({
        integrations: {
          packetfence: {
            base_url: formData.baseUrl,
            username: formData.username.trim(),
            ...(formData.passwordUnchanged
              ? {}
              : { password: formData.password }),
            enabled: formData.enabled,
            managed_event_types: parseEventTypes(formData.managedEventTypes),
            require_exclusive_ownership: true,
            policy_checks_required: Number(formData.policyChecks),
            cve_checks_required: Number(formData.cveChecks),
            dry_run: formData.dryRun,
          },
        },
      });
      notify.success("Successfully saved PacketFence settings.");
      await queryClient.invalidateQueries(["config"]);
    } catch (e) {
      notify.error("Could not save PacketFence settings.", { response: e });
    } finally {
      setIsUpdating(false);
    }
  };

  const renderConnectionStatus = () => {
    switch (connection.state) {
      case "success":
        return (
          <p className={`${baseClass}__status ${baseClass}__status--success`}>
            {connection.message}
          </p>
        );
      case "error":
        return (
          <p className={`${baseClass}__status ${baseClass}__status--error`}>
            {connection.message}
          </p>
        );
      default:
        return (
          <p className={`${baseClass}__status`}>
            Connection has not been tested with these settings.
          </p>
        );
    }
  };

  return (
    <div className={baseClass}>
      <SectionHeader title="PacketFence" />
      <PageDescription
        content={
          <>
            Connect Fleet to PacketFence to automatically clear Fleet-owned
            security events after affected hosts recover. Only enter event types
            dedicated exclusively to Fleet. Shared event types must not be
            configured.
          </>
        }
        variant="right-panel"
      />
      <form onSubmit={onFormSubmit} autoComplete="off">
        <div className={`${baseClass}__section`}>
          <h3 className={`${baseClass}__section-title`}>Connection</h3>
          <InputField
            label="PacketFence URL"
            onChange={onInputChange}
            name="baseUrl"
            value={formData.baseUrl}
            parseTarget
            placeholder="https://packetfence.example.com"
            error={formErrors.baseUrl}
            disabled={gomEnabled}
            helpText="Absolute https URL of the PacketFence Unified API."
          />
          <InputField
            label="Username"
            onChange={onInputChange}
            name="username"
            value={formData.username}
            parseTarget
            placeholder="fleet-revocation-service"
            error={formErrors.username}
            disabled={gomEnabled}
            helpText="Dedicated service account with SECURITY_EVENTS_READ and NODES_UPDATE permissions."
          />
          <InputField
            type="password"
            label="Password"
            onChange={onInputChange}
            name="password"
            value={formData.password}
            parseTarget
            error={formErrors.password}
            disabled={gomEnabled}
            helpText={
              formData.passwordUnchanged
                ? "Password is configured. Enter a new password to update."
                : undefined
            }
          />
          <div className={`${baseClass}__test-row`}>
            <Button
              type="button"
              variant="secondary"
              onClick={onTestConnection}
              disabled={gomEnabled}
              isLoading={connection.state === "testing"}
            >
              Test connection
            </Button>
            {renderConnectionStatus()}
          </div>
        </div>

        <div className={`${baseClass}__section`}>
          <h3 className={`${baseClass}__section-title`}>
            Automatic event clearing
          </h3>
          <Slider
            value={formData.enabled}
            onChange={onToggleEnabled}
            activeText="Automatic event clearing is on"
            inactiveText="Automatic event clearing is off"
            ariaLabel="Automatic PacketFence event clearing"
            helpText="Fleet requests closure only after all associated findings recover and verifies the event is closed before marking it cleared."
            disabled={gomEnabled}
          />
        </div>

        {formData.enabled && (
          <div className={`${baseClass}__section`}>
            <h3 className={`${baseClass}__section-title`}>Safety settings</h3>
            <InputField
              label="Managed security event types"
              onChange={onInputChange}
              name="managedEventTypes"
              value={formData.managedEventTypes}
              parseTarget
              placeholder="Enter Fleet-dedicated event type IDs"
              error={formErrors.managedEventTypes}
              disabled={gomEnabled}
              helpText="Comma-separated PacketFence event type IDs dedicated exclusively to Fleet."
            />
            <InputField
              label="Policy recovery checks"
              onChange={onInputChange}
              name="policyChecks"
              value={formData.policyChecks}
              parseTarget
              type="number"
              error={formErrors.policyChecks}
              disabled={gomEnabled}
              helpText="Distinct passing policy evaluations required before clearing."
            />
            <InputField
              label="CVE recovery cycles"
              onChange={onInputChange}
              name="cveChecks"
              value={formData.cveChecks}
              parseTarget
              type="number"
              error={formErrors.cveChecks}
              disabled={gomEnabled}
              helpText="Complete post-remediation inventory and vulnerability-processing cycles required before clearing."
            />
            <Checkbox
              onChange={({ name, value }: IInputFieldParseTarget) =>
                setFormData({ ...formData, [name]: value })
              }
              name="dryRun"
              value={formData.dryRun}
              parseTarget
            >
              <TooltipWrapper tipContent="Evaluate recovery and record decisions without closing PacketFence events.">
                Dry run
              </TooltipWrapper>
            </Checkbox>
          </div>
        )}

        <div className="button-wrap">
          <GitOpsModeTooltipWrapper
            renderChildren={(disableChildren) => (
              <Button
                type="submit"
                disabled={Object.keys(formErrors).length > 0 || disableChildren}
                isLoading={isUpdating}
              >
                Save
              </Button>
            )}
          />
        </div>
      </form>
      {showEnableModal && (
        <EnableAutoClearModal
          baseUrl={formData.baseUrl}
          managedEventTypes={parseEventTypes(formData.managedEventTypes)}
          policyChecks={formData.policyChecks}
          cveChecks={formData.cveChecks}
          dryRun={formData.dryRun}
          onCancel={() => setShowEnableModal(false)}
          onConfirm={onConfirmEnable}
        />
      )}
    </div>
  );
};

export default PacketFence;
