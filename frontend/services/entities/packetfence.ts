import sendRequest from "services";
import endpoints from "utilities/endpoints";

export interface IPacketFenceTestConnectionRequest {
  base_url: string;
  username: string;
  // Send "********" to reuse the stored password.
  password: string;
}

export interface IPacketFenceTestConnectionResponse {
  connected: boolean;
  message?: string;
}

export default {
  testConnection: (
    data: IPacketFenceTestConnectionRequest
  ): Promise<IPacketFenceTestConnectionResponse> => {
    const { PACKETFENCE_TEST_CONNECTION } = endpoints;
    return sendRequest("POST", PACKETFENCE_TEST_CONNECTION, data);
  },
};
