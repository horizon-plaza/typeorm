import { parse, Statement } from "pgsql-ast-parser";
import { ObjectLiteral } from "..";
import { QueryExpressionMap } from "../query-builder/QueryExpressionMap";
import {
  DeleteData,
  DeleteWhereParameter,
  InsertData,
  SelectColumn,
  SelectData,
  UpdateColumn,
  UpdateData,
  ValueParameter,
  WhereParameter,
} from "./interfaces";

export class QueryInterceptor {
  private columns: ObjectLiteral[] = [];
  private sql: string;
  private statement: Statement;
  private parameters: ObjectLiteral;
  private expressionMap: QueryExpressionMap;
  public query: string;

  constructor(
    query: string,
    parameters: ObjectLiteral,
    expressionMap: QueryExpressionMap
  ) {
    this.query = query;
    this.sql = query.toLowerCase();
    this.parameters = parameters;
    this.expressionMap = expressionMap;
    this.init();
  }

  private getColumnsSqlAndStatement(): void {
    this.expressionMap.aliases
      .filter((alias) => alias.hasMetadata)
      .forEach((alias) => {
        alias.metadata.columns.forEach((column) => {
          if (column?.encryptionKey) {
            this.columns.push({
              column: column.propertyPath,
              encryptionKey: column?.encryptionKey,
              table: alias.metadata.tableName,
              type: column.type,
            });
          }
        });
      });

    if (this.columns.length > 0) {
      if (Object.keys(this.parameters).length > 0) {
        this.sql = this.query
          .replace(
            new RegExp(
              Object.keys(this.parameters)
                .map((key) => ":" + key)
                .join("|"),
              "gi"
            ),
            (parameter) => `"${parameter.replace(":", "")}"`
          )
          .toLowerCase();
      }
      this.statement = parse(this.sql)[0];
    }
  }

  private getSelectData(): SelectData {
    const data: SelectData = {
      columns: [],
      wheres: [],
    };
    if (this.statement.type === "select") {
      const required = this.getRequiredColumns();
      const input: SelectColumn[] =
        (this.statement.columns?.filter(
          (column) => column.expr.type === "ref"
        ) as SelectColumn[]) ?? [];
      data.columns = input
        .map((column) => {
          const table = column.expr.table?.name ?? "";
          return {
            table: table.charAt(0).toUpperCase() + table.slice(1),
            column: column.expr.name,
          };
        })
        .filter((column) => required.includes(column.column))
        .map((column) => {
          const encryptionKey = this.getEncryptionKey(column.column);
          return {
            ...column,
            encryptionKey,
          };
        });
      if (this.statement.where) {
        const excludedColumns = data.columns.map((column) => column.column);
        data.wheres = this.getWheres(this.statement.where, excludedColumns);
      }
    }

    return data;
  }

  private getInsertData(): InsertData {
    const data: InsertData = {
      values: [],
    };
    if (
      this.statement.type === "insert" &&
      this.statement.columns &&
      this.statement.insert.type === "values"
    ) {
      const values = this.statement.insert.values[0] ?? [];
      const columns = this.statement.columns ?? [];
      const required = this.getRequiredColumns();
      const parameters: ValueParameter[] = columns
        .map((item, index) => {
          const column = item.name;
          const value = values[index];
          const parameter = value.type === "ref" ? value.name : "";
          return {
            column,
            parameter,
          };
        })
        .filter((item) => required.includes(item.column))
        .map((item) => {
          const { column, parameter } = item;
          const encryptionKey = this.getEncryptionKey(column);
          return {
            parameter,
            encryptionKey,
          };
        });
      data.values = parameters;
    }
    return data;
  }

  private getUpdateData(): UpdateData {
    const data: UpdateData = {
      columns: [],
      wheres: [],
    };
    if (this.statement.type === "update") {
      const table = this.statement.table.name;
      const required = this.getRequiredColumns();
      const input: UpdateColumn[] =
        (this.statement.sets.filter((set) =>
          required.includes(set.column.name)
        ) as UpdateColumn[]) ?? [];
      data.columns = input.map((item) => {
        const column = item.column.name;
        const parameter = item.value.name;
        const encryptionKey = this.getEncryptionKey(column);
        return {
          table,
          column,
          parameter,
          encryptionKey,
        };
      });
      if (this.statement.where) {
        const excludedColumns = data.columns.map((column) => column.column);
        data.wheres = this.getWheres(this.statement.where, excludedColumns);
      }
    }
    return data;
  }

  private getDeleteData(): DeleteData {
    const data: DeleteData = {
      wheres: [],
    };
    if (this.statement.type === "delete") {
      const where = this.statement.where;
      if (where) {
        const table = this.statement.from.name;
        const wheres = this.getDeleteWheres(table, where);
        data.wheres = wheres;
      }
    }
    return data;
  }

  private getWheres(where: any, excludedColumns: string[]): WhereParameter[] {
    const wheres: WhereParameter[] = [];
    if (where.left.type === "binary" && where.right.type === "binary") {
      wheres.push(...this.getWheres(where.left, excludedColumns));
      wheres.push(...this.getWheres(where.right, excludedColumns));
    } else {
      const column = where.left.name;
      const metadata = this.columns.find(
        (columns) => columns.column === column
      );
      if (metadata && !excludedColumns.includes(column)) {
        const parameter = where.right?.name ?? where.right.value;
        wheres.push({
          table: where.left.table.name,
          column,
          parameter,
          encryptionKey: metadata.encryptionKey,
        });
      }
    }
    return wheres;
  }

  private getDeleteWheres(table: string, where: any): DeleteWhereParameter[] {
    const wheres: DeleteWhereParameter[] = [];
    if (where.left.type === "binary" && where.right.type === "binary") {
      wheres.push(...this.getDeleteWheres(table, where.left));
      wheres.push(...this.getDeleteWheres(table, where.right));
    } else {
      const column = where.left.name;
      const metadata = this.columns.find(
        (columns) => columns.column === column
      );
      if (metadata) {
        const parameter = where.right?.name ?? where.right.value;
        const encryptionKey = metadata.encryptionKey;
        wheres.push({
          table,
          column,
          parameter,
          encryptionKey,
        });
      }
    }
    return wheres;
  }

  private encryptParameter(parameter: any, encryptionKey: string) {
    return `PGP_SYM_ENCRYPT(${parameter}, MERGEKEY('${encryptionKey}'), 'compress-algo=1, cipher-algo=aes256')`;
  }

  private decryptColumn(column: string, encryptionKey: string) {
    return `PGP_SYM_DECRYPT(${column}::bytea, MERGEKEY('${encryptionKey}'), 'compress-algo=1, cipher-algo=aes256')`;
  }

  private modifySelectStatement(modifications: SelectData) {
    modifications.columns.forEach((modification) => {
      const { table, column, encryptionKey } = modification;
      const decrypted = `"${table}"."${column}"`;
      this.query = this.query.replace(
        new RegExp(decrypted, "g"),
        this.decryptColumn(decrypted, encryptionKey)
      );
    });
    modifications.wheres.forEach((modification) => {
      const { table, column, encryptionKey } = modification;
      const decrypted = `"${table}"."${column}"`;
      this.query = this.query.replace(
        new RegExp(decrypted, "g"),
        this.decryptColumn(decrypted, encryptionKey)
      );
    });
  }

  private modifyInsertStatement(modifications: InsertData) {
    modifications.values.forEach((modification) => {
      const { parameter, encryptionKey } = modification;
      const encrypted = `:${parameter}`;
      this.query = this.query.replace(
        new RegExp(encrypted, "g"),
        this.encryptParameter(encrypted, encryptionKey)
      );
    });
  }

  private modifyUpdateStatement(modifications: UpdateData) {
    const query = this.query.split(" WHERE ");
    modifications.columns.forEach((modification) => {
      const { parameter, encryptionKey } = modification;
      const encrypted = `:${parameter}`;
      query[0] = query[0].replace(
        new RegExp(encrypted, "g"),
        this.encryptParameter(encrypted, encryptionKey)
      );
    });
    modifications.columns.forEach((modification) => {
      const { column, encryptionKey } = modification;
      const decrypted = `"${column}"`;
      query[1] = query[1].replace(
        new RegExp(decrypted, "g"),
        this.decryptColumn(decrypted, encryptionKey)
      );
    });
    this.query = query.join(" WHERE ");
  }

  private modifyDeleteStatement(modifications: DeleteData) {
    modifications.wheres.forEach((modification) => {
      const { column, encryptionKey } = modification;
      const decrypted = `"${column}"`;
      this.query = this.query.replace(
        new RegExp(decrypted, "g"),
        this.decryptColumn(decrypted, encryptionKey)
      );
    });
  }

  private getEncryptionKey(column: string) {
    return this.columns.find((item) => item.column === column)?.encryptionKey;
  }

  private getRequiredColumns(): string[] {
    return this.columns.map((column) => column.column);
  }

  private init(): void {
    this.getColumnsSqlAndStatement();
    // currently we are only interested in select, insert, update and delete.
    // any other sql types will pass through gracefully.
    if (this.columns.length > 0) {
      switch (this.statement.type) {
        case "select":
          const select = this.getSelectData();
          this.modifySelectStatement(select);
          break;
        case "insert":
          const insert = this.getInsertData();
          this.modifyInsertStatement(insert);
          break;
        case "update":
          const update = this.getUpdateData();
          this.modifyUpdateStatement(update);
          break;
        case "delete":
          const deletion = this.getDeleteData();
          this.modifyDeleteStatement(deletion);
          break;
      }
    }
  }
}
