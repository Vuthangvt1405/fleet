import React, { useState } from "react";

import Button from "components/buttons/Button";
import InputField from "components/forms/fields/InputField";
import { ISendMessageFormData } from "interfaces/message";

const baseClass = "send-message-form";

interface ISendMessageFormProps {
  isSending: boolean;
  onSend: (formData: ISendMessageFormData) => void;
}

const SendMessageForm = ({
  isSending,
  onSend,
}: ISendMessageFormProps): JSX.Element => {
  const [hostId, setHostId] = useState("");
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [hostError, setHostError] = useState<string | null>(null);

  type ParsedTarget = { name: string; value: string };

  const onFieldChange = ({ name, value }: ParsedTarget) => {
    if (name === "host_id") {
      setHostId(value);
      setHostError(null);
    } else if (name === "title") {
      setTitle(value);
    } else {
      setBody(value);
    }
  };

  const onSubmitForm = (evt: React.FormEvent) => {
    evt.preventDefault();
    const parsedHostId = Number(hostId);
    if (!hostId || !Number.isInteger(parsedHostId) || parsedHostId <= 0) {
      setHostError("Enter a valid host ID.");
      return;
    }
    if (!title.trim() || !body.trim()) {
      return;
    }
    onSend({ host_id: parsedHostId, title: title.trim(), body: body.trim() });
  };

  const isValid =
    hostId.trim() !== "" && title.trim() !== "" && body.trim() !== "";

  return (
    <form className={`${baseClass}`} onSubmit={onSubmitForm}>
      <InputField
        error={hostError}
        parseTarget
        name="host_id"
        onChange={onFieldChange}
        value={hostId}
        label="Host ID"
        placeholder="e.g. 42"
        type="text"
      />
      <InputField
        parseTarget
        name="title"
        onChange={onFieldChange}
        value={title}
        label="Title"
        placeholder="Message title"
      />
      <InputField
        parseTarget
        name="body"
        onChange={onFieldChange}
        value={body}
        label="Body"
        type="textarea"
        placeholder="Message shown on the host"
      />
      <div className={`${baseClass}__actions`}>
        <Button type="submit" isLoading={isSending} disabled={!isValid}>
          Send message
        </Button>
      </div>
    </form>
  );
};

export default SendMessageForm;
