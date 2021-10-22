package io.trino.spi.security.SystemAccessControl


filterTables[tt]{
    table_allowed(input.catalogName,input.tableNames[i].schema,input.tableNames[i].table)
    tt = input.tableNames[i]
}


filterColumns[cc]{
	regex.match(getValuesOrAll(table_rules[i],"catalog")[_],input.table.catalog)
    input.table.schemaTable.schema == "information_schema"
    cc = input.columns[i]
}


default checkCanShowTables = false
checkCanShowTables{
    schema := input.table.schemaTable.schema
    catalog := input.table.catalog
    regex.match(getValuesOrAll(table_rules[i],"catalog")[_],catalog)
    regex.match(getValuesOrAll(table_rules[i],"user")[_],input.context.identity.user)
    matchGroups(getValuesOrAll(table_rules[i],"group"),input.context.identity.groups)
    regex.match(getValuesOrAll(table_rules[i],"schema")[_],schema)
}
