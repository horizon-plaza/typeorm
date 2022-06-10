import { PGNode, Name, ExprRef } from "pgsql-ast-parser";

export interface SelectColumn extends PGNode {
  expr: ExprRef;
  alias: Name;
}

export interface UpdateColumn extends PGNode {
  column: Name;
  value: {
    name: string;
  };
}

export interface SelectData {
  columns: {
    encryptionKey: string;
    table: string | undefined;
    column: string;
  }[];
  wheres: WhereParameter[];
}

export interface UpdateData {
  columns: {
    table: string;
    column: string;
    parameter: string;
    encryptionKey: string;
  }[];
  wheres: WhereParameter[];
}

export interface InsertData {
  values: ValueParameter[];
}

export interface DeleteData {
  wheres: DeleteWhereParameter[];
}

export interface ValueParameter {
  parameter: string;
  encryptionKey: string;
}

export interface WhereParameter {
  table: string;
  column: string;
  parameter: string;
  encryptionKey: string;
}

export interface DeleteWhereParameter {
  table: string;
  column: string;
  parameter: string;
  encryptionKey: string;
}