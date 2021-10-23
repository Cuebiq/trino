package io.trino.spi.security.SystemAccessControl


filterTables[tt]{
    table_allowed(input.catalogName,input.tableNames[i].schema,input.tableNames[i].table)
    tt = input.tableNames[i]
}


default checkCanShowTables = false
checkCanShowTables{
    schema := input.table.schemaTable.schema
    catalog := input.table.catalog
    match(table_rules[i],"catalog",catalog)
    match(table_rules[i],"user",input.context.identity.user)
    matchAnyInArray(table_rules[i],"group",input.context.identity.groups)
    match(table_rules[i],"schema",schema)
}
