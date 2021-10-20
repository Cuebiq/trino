package io.trino.spi.security.SystemAccessControl

table_rules = data.table_rules.tables
default checkCanSelectFromColumns = false


checkCanSelectFromColumns{
	regex.match(getValuesOrAll(table_rules[i],"catalog")[_],input.table.catalog)
    input.table.schemaTable.schema == "information_schema"
}

checkCanSelectFromColumns{
    rule_to_apply := filter_table_rules[0]
    all_columns_allowed(columns,rule_to_apply)
    rule_to_apply.privileges[_] == ["SELECT","GRANT_SELECT"][_]

}

filter_table_rules = rules{
	schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
    catalog := input.table.catalog
    rules=[ r| r = table_rules[i];
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
