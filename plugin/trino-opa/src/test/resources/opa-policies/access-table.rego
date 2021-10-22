package io.trino.spi.security.SystemAccessControl

table_rules = data.rules.tables


filterTables[tt]{
    table_allowed(input.catalogName,input.tableNames[i].schema,input.tableNames[i].table)
    tt = input.tableNames[i]
}


filterColumns[cc]{
	regex.match(getValuesOrAll(table_rules[i],"catalog")[_],input.table.catalog)
    input.table.schemaTable.schema == "information_schema"
    cc = input.columns[i]
}

filterColumns[cc]{
	regex.match(getValuesOrAll(table_rules[i],"catalog")[_],input.table.catalog)
    count({x|x=filter_table_rules[0].privileges[i]} - {"SELECT","GRANT_SELECT"}) > 0
    cc = input.columns[i]
}


filterColumns[cc]{
	regex.match(getValuesOrAll(table_rules[_],"catalog")[_],input.table.catalog)
    column_allowed(input.columns[i],column_rules(filter_table_rules[0]))
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

table_allowed(catalog,schema,table){
    isSchemaOwner(catalog,schema)
}

default table_allowed(catalog,schema,table) = false
table_allowed(catalog,schema,table){
    can_access_catalog(catalog,"READ_ONLY")
    rule_to_apply := filter_table_rules[0]
   	regex.match(getValuesOrAll(rule_to_apply,"catalog")[_],catalog)
    regex.match(getValuesOrAll(rule_to_apply,"user")[_],input.context.identity.user)
    matchGroups(getValuesOrAll(rule_to_apply,"group"),input.context.identity.groups)
    regex.match(getValuesOrAll(rule_to_apply,"schema")[_],schema)
    regex.match(getValuesOrAll(rule_to_apply,"table")[_],table)
    count(rule_to_apply.privileges) > 0
}




default checkCanShowColumns = false
checkCanShowColumns{
    rule_to_apply := filter_table_rules[0]
    all_columns_allowed(columns,rule_to_apply)
    count(rule_to_apply.privileges) > 0
}


default checkCanCreateViewWithSelectFromColumns = "default-exception"

checkCanCreateViewWithSelectFromColumns = "" {
	regex.match(getValuesOrAll(table_rules[i],"catalog")[_],input.table.catalog)
    input.table.schemaTable.schema == "information_schema"
}

checkCanCreateViewWithSelectFromColumns = concat(" ",["View owner '",input.context.identity.user,"' cannot create view that selects from",input.table.schemaTable.table])
{
    rule_to_apply := filter_table_rules[0]
    all_columns_allowed(columns,rule_to_apply)
    not has_privileges(rule_to_apply.privileges,["GRANT_SELECT"])
}



checkCanCreateViewWithSelectFromColumns = ""{
    rule_to_apply := filter_table_rules[0]
    all_columns_allowed(columns,rule_to_apply)
    has_privileges(rule_to_apply.privileges,["GRANT_SELECT"])
}


default checkCanSelectFromColumns = false


checkCanSelectFromColumns{
	regex.match(getValuesOrAll(table_rules[i],"catalog")[_],input.table.catalog)
    input.table.schemaTable.schema == "information_schema"
}

checkCanSelectFromColumns{
    rule_to_apply := filter_table_rules[0]
    all_columns_allowed(columns,rule_to_apply)
    has_privileges(rule_to_apply.privileges,["SELECT","GRANT_SELECT"])
}

filter_table_rules = rules{
	schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
    catalog := input.table.catalog
    rules= [ r| r = table_rules[i];
    	regex.match(getValuesOrAll(r,"catalog")[_],catalog)
	    regex.match(getValuesOrAll(r,"user")[_],input.context.identity.user)
        matchGroups(getValuesOrAll(r,"group"),input.context.identity.groups)
    	regex.match(getValuesOrAll(r,"schema")[_],schema)
   	 	regex.match(getValuesOrAll(r,"table")[_],table)
    ]
}

default matchGroups(group_rules,user_groups) = false
matchGroups(group_rules,user_groups){
	regex.match(group_rules[_],user_groups[j])
}
matchGroups(group_rules,user_groups){
	count(input.context.identity.groups)==0
}

columns = input.columns
{
	input.columns
} else = []

all_columns_allowed(columns, table_rule)
{
	count({x | columns[x]; not column_allowed(columns[x],column_rules(table_rule))}) == 0
}

all_columns_allowed(columns, table_rule)
{
	count(columns) == 0
}

column_rules(table_rule) = table_rule.columns
{
	 table_rule.columns
}else = []


default column_allowed(column, column_rules) = false
column_allowed(column, column_rules){
	regex.match(getValuesOrAll(column_rules[i],"name")[_],column)
    allow(column_rules[i])
}

column_allowed(column, column_rules)
{
	count({x|column_rules[x];regex.match(getValuesOrAll(column_rules[x],"name")[_],column)}) == 0
}

allow(column_rule) = allow_value
{
    allow_value := column_rule.allow
}else = true

default has_privileges(privileges, requested) = false
has_privileges(privileges, requested)
{
	privileges[_] == requested[_]
}

