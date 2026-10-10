import React from "react";

import HeaderCell from "components/TableContainer/DataTable/HeaderCell";
import TextCell from "components/TableContainer/DataTable/TextCell";
import TooltipTruncatedTextCell from "components/TableContainer/DataTable/TooltipTruncatedTextCell";
import { IMessage, MessageStatusToDisplayCopy } from "interfaces/message";

interface IHeaderProps {
  column: {
    title: string;
    isSortedDesc: boolean;
  };
}

interface IRowProps {
  row: {
    original: IMessage;
  };
}

interface ICellProps extends IRowProps {
  cell: {
    value: string;
  };
}

interface IDataColumn {
  title: string;
  Header: ((props: IHeaderProps) => JSX.Element) | string;
  accessor: string;
  Cell: (props: ICellProps) => JSX.Element;
  disableHidden?: boolean;
  disableSortBy?: boolean;
  sortType?: string;
}

const generateTableHeaders = (): IDataColumn[] => {
  return [
    {
      title: "Sent at",
      Header: (cellProps) => (
        <HeaderCell
          value={cellProps.column.title}
          isSortedDesc={cellProps.column.isSortedDesc}
        />
      ),
      accessor: "created_at",
      Cell: (cellProps: ICellProps) => (
        <TextCell value={cellProps.cell.value} />
      ),
    },
    {
      title: "To",
      Header: (cellProps) => (
        <HeaderCell
          value={cellProps.column.title}
          isSortedDesc={cellProps.column.isSortedDesc}
        />
      ),
      accessor: "hostname",
      Cell: (cellProps: ICellProps) => {
        const message = cellProps.row.original;
        const value = message.user_email
          ? `${message.hostname} (${message.user_email})`
          : message.hostname;
        return <TooltipTruncatedTextCell value={value} />;
      },
    },
    {
      title: "Title",
      Header: (cellProps) => (
        <HeaderCell
          value={cellProps.column.title}
          isSortedDesc={cellProps.column.isSortedDesc}
        />
      ),
      accessor: "title",
      Cell: (cellProps: ICellProps) => (
        <TooltipTruncatedTextCell value={cellProps.cell.value} />
      ),
    },
    {
      title: "Body",
      Header: (cellProps) => (
        <HeaderCell
          value={cellProps.column.title}
          isSortedDesc={cellProps.column.isSortedDesc}
        />
      ),
      accessor: "body",
      disableSortBy: true,
      Cell: (cellProps: ICellProps) => (
        <TooltipTruncatedTextCell value={cellProps.cell.value} />
      ),
    },
    {
      title: "Trigger",
      Header: (cellProps) => (
        <HeaderCell
          value={cellProps.column.title}
          isSortedDesc={cellProps.column.isSortedDesc}
        />
      ),
      accessor: "policy_name",
      Cell: (cellProps: ICellProps) => (
        <TooltipTruncatedTextCell
          value={cellProps.row.original.policy_name || "Manual"}
        />
      ),
    },
    {
      title: "Status",
      Header: (cellProps) => (
        <HeaderCell
          value={cellProps.column.title}
          isSortedDesc={cellProps.column.isSortedDesc}
        />
      ),
      accessor: "status",
      Cell: (cellProps: ICellProps) => {
        const status = cellProps.row.original.status;
        return <TextCell value={MessageStatusToDisplayCopy[status]} />;
      },
    },
    {
      title: "Sent by",
      Header: (cellProps) => (
        <HeaderCell
          value={cellProps.column.title}
          isSortedDesc={cellProps.column.isSortedDesc}
        />
      ),
      accessor: "sender_name",
      Cell: (cellProps: ICellProps) => (
        <TextCell value={cellProps.cell.value || ""} />
      ),
    },
  ];
};

const generateDataSet = (messages: IMessage[]) => messages;

export { generateTableHeaders, generateDataSet };
