import React, { memo } from "react";

import EmptyState from "components/EmptyState";
import TableContainer from "components/TableContainer";
import TableCount from "components/TableContainer/TableCount";
import { IMessage } from "interfaces/message";

import { generateDataSet, generateTableHeaders } from "./MessagesTableConfig";

const baseClass = "messages-table";

interface IMessagesTableProps {
  messages: IMessage[];
}

const MessagesTable = ({ messages }: IMessagesTableProps) => {
  const tableHeaders = generateTableHeaders();
  const tableData = generateDataSet(messages);

  return (
    <TableContainer
      className={baseClass}
      isLoading={false}
      columnConfigs={tableHeaders}
      data={tableData}
      defaultSortHeader="created_at"
      defaultSortDirection="desc"
      resultsTitle="messages"
      showMarkAllPages={false}
      isAllPagesSelected={false}
      isClientSidePagination
      renderCount={() =>
        tableData.length ? (
          <TableCount name="messages" count={tableData.length} />
        ) : null
      }
      emptyComponent={() => (
        <EmptyState
          header="No messages sent"
          info="Messages you send to hosts will appear here."
        />
      )}
    />
  );
};

export default memo(MessagesTable);
