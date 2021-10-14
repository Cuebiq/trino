package io.trino.spi.security.SystemAccessControl

config = data.example


getColumnMask =  {
	 "identity": input.context.identity.user,
     "catalog": input.tableName.catalog,
     "schema": input.tableName.schemaTable.schema,
     "expression": config.rules[i].expression
}{
    some i
	input.tableName.catalog = config.rules[i].catalog
	input.tableName.schemaTable.schema = config.rules[i].schema
	input.tableName.schemaTable.table = config.rules[i].table
	input.columnName = config.rules[i].column
}
