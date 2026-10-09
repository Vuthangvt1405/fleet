import PropTypes from "prop-types";

export default PropTypes.shape({
  id: PropTypes.number,
  host_id: PropTypes.number,
  hostname: PropTypes.string,
  user_email: PropTypes.string,
  title: PropTypes.string,
  body: PropTypes.string,
  status: PropTypes.oneOf(["queued", "sent", "failed"]),
  created_at: PropTypes.string,
  sender_name: PropTypes.string,
});

export type MessageStatus = "queued" | "sent" | "failed";

export const MessageStatusToDisplayCopy: Record<MessageStatus, string> = {
  queued: "Queued",
  sent: "Sent",
  failed: "Failed",
};

/** A single message sent to a host (history row). */
export interface IMessage {
  id: number;
  host_id: number;
  hostname: string;
  user_email?: string;
  title: string;
  body: string;
  status: MessageStatus;
  created_at: string;
  sender_name?: string;
}

export interface IMessagesResponse {
  messages: IMessage[];
}

export interface ISendMessageResponse {
  message: IMessage;
}

/** Form data for composing a message for one or more hosts. */
export interface ISendMessageFormData {
  host_ids: number[];
  title: string;
  body: string;
}

/** Request body for sending one message to one host. */
export interface ISendSingleMessageRequest {
  host_id: number;
  title: string;
  body: string;
}
