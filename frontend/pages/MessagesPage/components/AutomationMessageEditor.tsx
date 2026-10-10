import React, { useEffect, useState } from "react";

import Button from "components/buttons/Button";

import {
  buildAutomationPreviewBody,
  buildAutomationPreviewTitle,
  DEFAULT_AUTOMATION_TITLE,
} from "./automationMessageHelpers";
import AutomationMessageModal from "./AutomationMessageModal";

const baseClass = "automation-message-editor";

interface IAutomationMessageEditorProps {
  canEdit: boolean;
  enabled: boolean;
  initialTitle?: string;
  initialAdditionalMessage?: string;
  isSaving: boolean;
  onSave: (formData: {
    enabled: boolean;
    title: string;
    additionalMessage: string;
  }) => Promise<boolean>;
}

const AutomationMessageEditor = ({
  canEdit,
  enabled,
  initialTitle,
  initialAdditionalMessage,
  isSaving,
  onSave,
}: IAutomationMessageEditorProps): JSX.Element => {
  const [savedTitle, setSavedTitle] = useState(
    initialTitle || DEFAULT_AUTOMATION_TITLE
  );
  const [savedAdditionalMessage, setSavedAdditionalMessage] = useState(
    initialAdditionalMessage || ""
  );
  const [isEnabled, setIsEnabled] = useState(enabled);
  const [showModal, setShowModal] = useState(false);

  useEffect(() => {
    setSavedTitle(initialTitle || DEFAULT_AUTOMATION_TITLE);
    setSavedAdditionalMessage(initialAdditionalMessage || "");
    setIsEnabled(enabled);
  }, [enabled, initialAdditionalMessage, initialTitle]);

  const previewTitle = buildAutomationPreviewTitle(savedTitle);
  const previewBody = buildAutomationPreviewBody(savedAdditionalMessage);

  return (
    <section className={baseClass} aria-labelledby={`${baseClass}__title`}>
      <div className={`${baseClass}__header`}>
        <div>
          <h2 id={`${baseClass}__title`}>PacketFence automation message</h2>
          <p>
            Preview the message Fleet could send when a policy trigger is sent
            to PacketFence.
          </p>
        </div>
        <span className={`${baseClass}__status`}>
          {isEnabled ? "Enabled" : "Disabled"}
        </span>
      </div>

      <div className={`${baseClass}__notice`} role="status">
        Messages are sent only when a policy webhook is delivered directly to
        the configured PacketFence instance.
      </div>

      <div className={`${baseClass}__preview`}>
        <h3>Current message</h3>
        <div className={`${baseClass}__preview-message`}>
          <strong>{previewTitle}</strong>
          <p>{previewBody}</p>
        </div>
      </div>

      <div className={`${baseClass}__actions`}>
        {canEdit ? (
          <Button variant="secondary" onClick={() => setShowModal(true)}>
            Edit message
          </Button>
        ) : (
          <p className={`${baseClass}__permission-note`}>
            A global admin can edit this message.
          </p>
        )}
      </div>

      {showModal && (
        <AutomationMessageModal
          initialTitle={savedTitle}
          initialAdditionalMessage={savedAdditionalMessage}
          initialEnabled={isEnabled}
          isSaving={isSaving}
          onCancel={() => setShowModal(false)}
          onSave={async ({
            enabled: nextEnabled,
            title,
            additionalMessage,
          }) => {
            const saved = await onSave({
              enabled: nextEnabled,
              title,
              additionalMessage,
            });
            if (!saved) return;
            setIsEnabled(nextEnabled);
            setSavedTitle(title);
            setSavedAdditionalMessage(additionalMessage);
            setShowModal(false);
          }}
        />
      )}
    </section>
  );
};

export default AutomationMessageEditor;
