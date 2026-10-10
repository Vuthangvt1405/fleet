import React, { useState } from "react";

import Button from "components/buttons/Button";
import InputField from "components/forms/fields/InputField";
import Slider from "components/forms/fields/Slider";
import Modal from "components/Modal";

import {
  buildAutomationPreviewBody,
  buildAutomationPreviewTitle,
  SAMPLE_POLICY_NAME,
} from "./automationMessageHelpers";

const baseClass = "automation-message-modal";

interface IAutomationMessageModalProps {
  initialEnabled: boolean;
  initialTitle: string;
  initialAdditionalMessage: string;
  isSaving: boolean;
  onSave: (formData: {
    enabled: boolean;
    title: string;
    additionalMessage: string;
  }) => Promise<boolean>;
  onCancel: () => void;
}

const AutomationMessageModal = ({
  initialEnabled,
  initialTitle,
  initialAdditionalMessage,
  isSaving,
  onSave,
  onCancel,
}: IAutomationMessageModalProps): JSX.Element => {
  const [enabled, setEnabled] = useState(initialEnabled);
  const [title, setTitle] = useState(initialTitle);
  const [additionalMessage, setAdditionalMessage] = useState(
    initialAdditionalMessage
  );

  const isValid = title.trim() !== "";
  const previewTitle = buildAutomationPreviewTitle(title);
  const previewBody = buildAutomationPreviewBody(additionalMessage);

  const onSaveClick = async () => {
    if (!isValid) {
      return;
    }
    await onSave({ enabled, title: title.trim(), additionalMessage });
  };

  return (
    <Modal
      title="Edit PacketFence automation message"
      onExit={onCancel}
      width="large"
      className={baseClass}
    >
      <p className={`${baseClass}__description`}>
        Preview the message Fleet could send when a policy trigger is sent to
        PacketFence. Fleet always includes the failed policy name and its
        configured resolution.
      </p>
      <Slider
        value={enabled}
        onChange={() => setEnabled((current) => !current)}
        ariaLabel="Enable PacketFence end-user notifications"
        activeText="User notifications are on"
        inactiveText="User notifications are off"
      />
      <div className={`${baseClass}__content`}>
        <div className={`${baseClass}__fields`}>
          <InputField
            autofocus
            label="Message title"
            name="automation-message-title"
            value={title}
            onChange={(value: string) => setTitle(value)}
            error={isValid ? null : "Title is required"}
            helpText={`Use {policy_name} to include the policy, for example “${SAMPLE_POLICY_NAME}”.`}
          />
          <InputField
            label="Additional message"
            name="automation-message-body"
            value={additionalMessage}
            onChange={(value: string) => setAdditionalMessage(value)}
            type="textarea"
            placeholder="Add extra context for the user"
          />
        </div>
        <div className={`${baseClass}__preview`}>
          <h3>Preview</h3>
          <div className={`${baseClass}__preview-message`}>
            <strong>{previewTitle || "Message title"}</strong>
            <p>{previewBody}</p>
          </div>
        </div>
      </div>
      <div className="modal-cta-wrap">
        <Button
          onClick={onSaveClick}
          disabled={!isValid || isSaving}
          isLoading={isSaving}
        >
          Save
        </Button>
        <Button variant="secondary" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </Modal>
  );
};

export default AutomationMessageModal;
