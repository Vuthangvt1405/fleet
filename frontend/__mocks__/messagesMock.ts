import { IMessage, IMessagesResponse } from "interfaces/message";

const DEFAULT_MESSAGE_MOCK: IMessage = {
  id: 1,
  host_id: 1,
  hostname: "WKS-0142",
  user_email: "ana@acme.com",
  title: "Blocked app detected",
  body: "This app is not allowed by IT. Please uninstall uTorrent.",
  status: "sent",
  created_at: "2026-10-01T10:42:00Z",
  sender_name: "Admin",
};

export const createMockMessage = (overrides?: Partial<IMessage>): IMessage => {
  return { ...DEFAULT_MESSAGE_MOCK, ...overrides };
};

const DEFAULT_MESSAGES_RESPONSE_MOCK: IMessagesResponse = {
  messages: [createMockMessage()],
};

export const createMockMessagesResponse = (
  overrides?: Partial<IMessagesResponse>
): IMessagesResponse => {
  return { ...DEFAULT_MESSAGES_RESPONSE_MOCK, ...overrides };
};
