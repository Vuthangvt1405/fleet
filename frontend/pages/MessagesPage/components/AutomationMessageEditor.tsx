import React, { useState } from "react";

import InputField from "components/forms/fields/InputField";

const baseClass = "automation-message-editor";

const SAMPLE_POLICY_NAME = "Windows Firewall enabled on all profiles";
const SAMPLE_POLICY_RESOLUTION =
  "The policy’s configured resolution will appear here.";
const DEFAULT_TITLE = "Action needed: {policy_name}";

interface IAutomationMessageEditorProps {
  canEdit: boolean;
}

const AutomationMessageEditor = ({
  canEdit,
}: IAutomationMessageEditorProps): JSX.Element => {
  const [title, setTitle] = useState(DEFAULT_TITLE);
  const [additionalMessage, setAdditionalMessage] = useState("");

  const previewTitle = title.replaceAll("{policy_name}", SAMPLE_POLICY_NAME);
  const reasonMessage = `This device failed the “${SAMPLE_POLICY_NAME}” policy.\n\nTo resolve this, ${SAMPLE_POLICY_RESOLUTION}`;
  const previewBody = [reasonMessage, additionalMessage.trim()]
    .filter(Boolean)
    .join("\n\n");

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
        <span className={`${baseClass}__status`}>Not connected</span>
      </div>

      <div className={`${baseClass}__notice`} role="status">
        This is a frontend preview. Changes aren’t saved, and messages aren’t
        sent until backend support is added.
      </div>

      <div className={`${baseClass}__content`}>
        <div className={`${baseClass}__fields`}>
          <InputField
            label="Message title"
            name="automation-message-title"
            value={title}
            onChange={(value) => setTitle(value)}
            disabled={!canEdit}
          />
          <InputField
            label="Additional message"
            name="automation-message-body"
            value={additionalMessage}
            onChange={(value) => setAdditionalMessage(value)}
            type="textarea"
            placeholder="Add extra context for the user"
            disabled={!canEdit}
            helpText="Fleet always includes the failed policy name and its configured resolution."
          />
          {!canEdit && (
            <p className={`${baseClass}__permission-note`}>
              A global admin can edit this message.
            </p>
          )}
        </div>

        <div className={`${baseClass}__preview`}>
          <h3>Preview</h3>
          <div className={`${baseClass}__preview-message`}>
            <strong>{previewTitle}</strong>
            <p>{previewBody}</p>
          </div>
        </div>
      </div>
    </section>
  );
};

export default AutomationMessageEditor;
