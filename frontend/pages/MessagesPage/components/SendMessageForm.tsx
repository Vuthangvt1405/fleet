import React, { useState } from "react";

import Button from "components/buttons/Button";
import InputField from "components/forms/fields/InputField";
import { IHost } from "interfaces/host";
import { ISendMessageFormData } from "interfaces/message";

import HostMultiSelect from "./HostMultiSelect";

const baseClass = "send-message-form";

interface ISendMessageFormProps {
  isSending: boolean;
  onSend: (formData: ISendMessageFormData) => Promise<number[]>;
}

const SendMessageForm = ({
  isSending,
  onSend,
}: ISendMessageFormProps): JSX.Element => {
  const [selectedHosts, setSelectedHosts] = useState<IHost[]>([]);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");

  type ParsedTarget = { name: string; value: string };

  const onFieldChange = ({ name, value }: ParsedTarget) => {
    if (name === "title") {
      setTitle(value);
    } else {
      setBody(value);
    }
  };

  const onSubmitForm = async (evt: React.FormEvent) => {
    evt.preventDefault();
    if (selectedHosts.length === 0) {
      return;
    }
    if (!title.trim() || !body.trim()) {
      return;
    }
    const failedHostIDs = await onSend({
      host_ids: selectedHosts.map((host) => host.id),
      title: title.trim(),
      body: body.trim(),
    });
    if (failedHostIDs.length > 0) {
      setSelectedHosts((currentHosts) =>
        currentHosts.filter((host) => failedHostIDs.includes(host.id))
      );
    }
  };

  const isValid =
    selectedHosts.length > 0 && title.trim() !== "" && body.trim() !== "";

  return (
    <form className={`${baseClass}`} onSubmit={onSubmitForm}>
      <HostMultiSelect
        selectedHosts={selectedHosts}
        onChange={setSelectedHosts}
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
