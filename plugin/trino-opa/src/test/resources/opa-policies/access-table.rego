package io.trino.spi.security.SystemAccessControl

table_rules = data.rules.tables


filterTables[tt]{
    table_allowed(input.catalogName,input.tableNames[i].schema,input.tableNames[i].table)
    tt = input.tableNames[i]
}


default checkCanShowTables = false
checkCanShowTables{
    schema := input.table.schemaTable.schema
    catalog := input.table.catalog
    can_access_catalog(input.table.catalog,"READ_ONLY")
    match(table_rules[i],"catalog",catalog)
    match(table_rules[i],"user",input.context.identity.user)
    matchAnyInArray(table_rules[i],"group",input.context.identity.groups)
    match(table_rules[i],"schema",schema)
}

default checkCanInsertIntoTable = false
checkCanInsertIntoTable = checkTablePermission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"INSERT")

default checkCanDropTable = false
checkCanDropTable = checkTablePermission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanGrantTablePrivilege = false
checkCanGrantTablePrivilege = checkTablePermission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanRevokeTablePrivilege = false
checkCanRevokeTablePrivilege = checkTablePermission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanShowCreateTable = false
checkCanShowCreateTable = checkTablePermission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanAddColumn = false
checkCanAddColumn = checkTablePermission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanDropColumn = false
checkCanDropColumn = checkTablePermission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanRenameColumn = false
checkCanRenameColumn = checkTablePermission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanSetTableAuthorization = false
checkCanSetTableAuthorization = checkTablePermission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanSetViewAuthorization = false
checkCanSetViewAuthorization = checkTablePermission(input.view.catalog,input.view.schemaTable.schema,input.view.schemaTable.table,"OWNERSHIP")

default checkCanSetTableComment = false
checkCanSetTableComment = checkTablePermission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanRenameTable = false
checkCanRenameTable{
    checkTablePermission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")
    checkTablePermission(input.newTable.catalog,input.newTable.schemaTable.schema,input.newTable.schemaTable.table,"OWNERSHIP")
}



default checkCanDeleteFromTable = false
checkCanDeleteFromTable = checkTablePermission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"DELETE")


default checkCanDropMaterializedView = false
checkCanDropMaterializedView = checkTablePermission(
    input.materializedView.catalog,
    input.materializedView.schemaTable.schema,
    input.materializedView.schemaTable.table,"OWNERSHIP")

default checkCanCreateMaterializedView = false
checkCanCreateMaterializedView = checkTablePermission(
    input.materializedView.catalog,
    input.materializedView.schemaTable.schema,
    input.materializedView.schemaTable.table,"OWNERSHIP")

default checkCanRefreshMaterializedView = false
checkCanRefreshMaterializedView = checkTablePermission(
    input.materializedView.catalog,
    input.materializedView.schemaTable.schema,
    input.materializedView.schemaTable.table,"UPDATE")




checkTablePermission(catalog,schema,table,privilege) = false {
    not can_access_catalog(input.table.catalog,requiredCatalogAccess(privilege))
} else = true {
    match(table_rules[i],"catalog",catalog)
    schema == "information_schema"
} else = true {
    rule_to_apply := filter_table_rules(catalog,schema,table)[0]
    all_columns_allowed(object.get(input,"columns",[]), rule_to_apply)
    has_privileges(rule_to_apply.privileges,[privilege])
}else = true {
    count(filter_table_rules(catalog,schema,table)) == 0
    count(input.columns) == 0
}
