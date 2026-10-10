import React, { useCallback, useContext, useState } from "react";
import { useQuery } from "react-query";

import DataError from "components/DataError";
import MainContent from "components/MainContent";
import PageDescription from "components/PageDescription";
import Spinner from "components/Spinner";
import { notify } from "components/ToastNotification";
import { AppContext } from "context/app";
import {
  IMessage,
  IMessagesResponse,
  ISendMessageFormData,
} from "interfaces/message";
import messagesAPI from "services/entities/messages";

import AutomationMessageEditor from "./components/AutomationMessageEditor";
import SendMessageForm from "./components/SendMessageForm";
import MessagesTable from "./MessagesTable";

const baseClass = "manage-messages-page";

const MessagesPage = (): JSX.Element => {
  const {
    isGlobalAdmin,
    isGlobalMaintainer,
    isAnyTeamMaintainerOrTeamAdmin,
    isGlobalTechnician,
    isAnyTeamTechnician,
  } = useContext(AppContext);

  const [isSending, setIsSending] = useState(false);
  const [formKey, setFormKey] = useState(0);

  const { data: messages, isLoading, error, refetch } = useQuery<
    IMessagesResponse,
    Error,
    IMessage[]
  >(["messages"], () => messagesAPI.list(), {
    select: (data) => data.messages,
  });

  const onSend = useCallback(
    async (formData: ISendMessageFormData): Promise<number[]> => {
      try {
        setIsSending(true);
        const results = await Promise.allSettled(
          formData.host_ids.map((host_id) =>
            messagesAPI.send({
              host_id,
              title: formData.title,
              body: formData.body,
            })
          )
        );
        const sentCount = results.filter(
          (result) => result.status === "fulfilled"
        ).length;
        const failedCount = results.length - sentCount;
        const failedHostIDs: number[] = [];
        results.forEach((result, index) => {
          if (result.status === "rejected") {
            failedHostIDs.push(formData.host_ids[index]);
          }
        });

        if (failedCount === 0) {
          notify.success(
            `Message sent to ${sentCount} ${
              sentCount === 1 ? "host" : "hosts"
            }.`
          );
          setFormKey((k) => k + 1);
        } else if (sentCount > 0) {
          notify.error(
            `Message sent to ${sentCount} of ${results.length} hosts. Select the failed hosts and try again.`
          );
        } else {
          notify.error("Couldn't send message to the selected hosts.");
        }
        refetch();
        return failedHostIDs;
      } catch (err) {
        notify.error("Couldn't send message.", { response: err });
        return formData.host_ids;
      } finally {
        setIsSending(false);
      }
    },
    [refetch]
  );

  // Mirrors the write gate used for labels (`canAddLabel`).
  const canSendMessage =
    isGlobalAdmin ||
    isGlobalMaintainer ||
    isAnyTeamMaintainerOrTeamAdmin ||
    isGlobalTechnician ||
    isAnyTeamTechnician;

  const renderHistory = useCallback(() => {
    if (isLoading || !messages) {
      return <Spinner />;
    }
    if (error) {
      return <DataError />;
    }
    return <MessagesTable messages={messages} />;
  }, [error, isLoading, messages]);

  return (
    <MainContent className={baseClass}>
      <div className={`${baseClass}__header-wrap`}>
        <div className={`${baseClass}__header`}>
          <div className={`${baseClass}__text`}>
            <div className={`${baseClass}__title`}>
              <h1>Messages</h1>
            </div>
            <PageDescription content="Send a message to one or more hosts." />
          </div>
        </div>
      </div>
      {canSendMessage && (
        <div className={`${baseClass}__send-form`}>
          <SendMessageForm
            key={formKey}
            isSending={isSending}
            onSend={onSend}
          />
        </div>
      )}
      <AutomationMessageEditor canEdit={isGlobalAdmin} />
      {renderHistory()}
    </MainContent>
  );
};

export default MessagesPage;
