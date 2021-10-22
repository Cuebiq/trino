package io.trino.spi.security.SystemAccessControl


filterColumns[cc]{
    catalog := input.table.catalog
    schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
	regex.match(getValuesOrAll(table_rules[i],"catalog")[_],input.table.catalog)
    count({x|x=filter_table_rules(catalog, schema, table)[0].privileges[i]} - {"SELECT","GRANT_SELECT"}) > 0
    cc = input.columns[i]
}


filterColumns[cc]{
    catalog := input.table.catalog
    schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
	regex.match(getValuesOrAll(table_rules[_],"catalog")[_],input.table.catalog)
    column_allowed(input.columns[i],column_rules(filter_table_rules(catalog, schema, table)[0]))
    cc = input.columns[i]
}

default checkCanShowColumns = false
checkCanShowColumns{
    catalog := input.table.catalog
    schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
    rule_to_apply := filter_table_rules(catalog,schema,table)[0]
    count(rule_to_apply.privileges) > 0
}



default checkCanSelectFromColumns = false

checkCanSelectFromColumns{
	regex.match(getValuesOrAll(table_rules[i],"catalog")[_],input.table.catalog)
    input.table.schemaTable.schema == "information_schema"
}

checkCanSelectFromColumns{
    catalog := input.table.catalog
    schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
    rule_to_apply := filter_table_rules(catalog,schema,table)[0]
    all_columns_allowed(orEmptyArray(input.columns),rule_to_apply)
    has_privileges(rule_to_apply.privileges,["SELECT","GRANT_SELECT"])
}

default checkCanCreateViewWithSelectFromColumns = "default-exception"

checkCanCreateViewWithSelectFromColumns = "" {
	regex.match(getValuesOrAll(table_rules[i],"catalog")[_],input.table.catalog)
    input.table.schemaTable.schema == "information_schema"
}

checkCanCreateViewWithSelectFromColumns = concat(" ",["View owner '",input.context.identity.user,"' cannot create view that selects from",input.table.schemaTable.table])
{
    catalog := input.table.catalog
    schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
    rule_to_apply := filter_table_rules(catalog,schema,table)[0]
    all_columns_allowed(orEmptyArray(input.columns),rule_to_apply)
    not has_privileges(rule_to_apply.privileges,["GRANT_SELECT"])
}

checkCanCreateViewWithSelectFromColumns = ""{
    catalog := input.table.catalog
    schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
    rule_to_apply := filter_table_rules(catalog,schema,table)[0]
    all_columns_allowed(orEmptyArray(input.columns),rule_to_apply)
    has_privileges(rule_to_apply.privileges,["GRANT_SELECT"])
}
