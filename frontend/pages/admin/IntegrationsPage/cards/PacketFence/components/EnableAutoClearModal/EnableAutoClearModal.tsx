import React from "react";

import Button from "components/buttons/Button";
import Modal from "components/Modal";

const baseClass = "enable-auto-clear-modal";

interface IEnableAutoClearModalProps {
  baseUrl: string;
  managedEventTypes: string[];
  policyChecks: string;
  cveChecks: string;
  dryRun: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

const EnableAutoClearModal = ({
  baseUrl,
  managedEventTypes,
  policyChecks,
  cveChecks,
  dryRun,
  onCancel,
  onConfirm,
}: IEnableAutoClearModalProps): JSX.Element => {
  return (
    <Modal
      title="Turn on automatic event clearing?"
      onExit={onCancel}
      onEnter={onConfirm}
      className={baseClass}
    >
      <div className={`${baseClass}__content`}>
        <p>
          Only enable this for PacketFence event types dedicated exclusively to
          Fleet. Every associated finding must recover first, and Fleet verifies
          the PacketFence event is closed before marking it cleared.
        </p>
        <dl className={`${baseClass}__summary`}>
          <div>
            <dt>PacketFence URL</dt>
            <dd>{baseUrl || "Not set"}</dd>
          </div>
          <div>
            <dt>Managed event types</dt>
            <dd>{managedEventTypes.join(", ") || "None"}</dd>
          </div>
          <div>
            <dt>Policy confirmations</dt>
            <dd>{policyChecks}</dd>
          </div>
          <div>
            <dt>CVE cycles</dt>
            <dd>{cveChecks}</dd>
          </div>
          <div>
            <dt>Dry run</dt>
            <dd>{dryRun ? "On" : "Off"}</dd>
          </div>
        </dl>
        <div className="modal-cta-wrap">
          <Button type="button" onClick={onConfirm} className="turn-on-loading">
            Turn on
          </Button>
          <Button onClick={onCancel} variant="secondary">
            Cancel
          </Button>
        </div>
      </div>
    </Modal>
  );
};

export default EnableAutoClearModal;
