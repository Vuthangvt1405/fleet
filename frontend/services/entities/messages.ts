import {
  IMessagesResponse,
  ISendMessageFormData,
  ISendMessageResponse,
} from "interfaces/message";
import sendRequest from "services";
import endpoints from "utilities/endpoints";

export default {
  /** History of messages sent to hosts, newest first. */
  list: (): Promise<IMessagesResponse> => {
    const { MESSAGES } = endpoints;
    return sendRequest("GET", MESSAGES);
  },

  /** Queue a message for a host. The agent shows it as a Windows toast. */
  send: (formData: ISendMessageFormData): Promise<ISendMessageResponse> => {
    const { MESSAGES } = endpoints;
    return sendRequest("POST", MESSAGES, {
      host_id: formData.host_id,
      title: formData.title,
      body: formData.body,
    });
  },
};
