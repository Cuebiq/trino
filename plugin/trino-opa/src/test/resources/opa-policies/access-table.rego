package io.trino.spi.security.SystemAccessControl

table_rules = data.table_rules.tables

default checkCanSelectFromColumns = false


checkCanSelectFromColumns{
	regex.match(getValuesOrAll(table_rules[i],"catalog")[_],input.table.catalog)
    input.table.schemaTable.schema == "information_schema"
}

checkCanSelectFromColumns{
    columns := input.columns
    schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
    catalog := input.table.catalog

    regex.match(getValuesOrAll(table_rules[i],"catalog")[_],catalog)
    regex.match(getValuesOrAll(table_rules[i],"user")[_],input.context.identity.user)
    regex.match(getValuesOrAll(table_rules[i],"group")[_],input.context.identity.groups[j])
    regex.match(getValuesOrAll(table_rules[i],"table")[_],table)
    count({x | columns[x];not column_allowed(columns[x],column_rules(table_rules[i]))}) == 0
}

column_rules(table_rule) = table_rules.columns
{
	 table_rules.columns
}else = []

column_allowed(column, column_rules){
    column == column_rules[i].name
    allow(column_rules[i])
}

allow(column_rule) = allow_value
{
    allow_value := column_rule.allow
}else = true


getValuesOrAll(o,field) =  split(o[field],"|")
{
	o[field]
} else = [".*"]
