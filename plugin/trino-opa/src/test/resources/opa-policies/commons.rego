package io.trino.spi.security.SystemAccessControl


schema_rules = data.rules.schemas
catalog_rules = data.catalogs { data.catalog } else = [{"catalog": ".*"}]
table_rules = data.rules.tables


default matchGroups(group_rules,user_groups) = false
matchGroups(group_rules,user_groups){
	regex.match(group_rules[_],user_groups[j])
}
matchGroups(group_rules,user_groups){
#	count(input.context.identity.groups)==0
	count(user_groups)==0
}

#equalsGroupOrMissing(obj, value)
#{
#    matchGroups(getValuesOrAll(obj,"group"),value)
#}

equalsGroupOrMissing(obj, value)
{
	groups = split(obj.group,"|")
	groups[_] == value
} else {
	not has_key(obj,"group")
}

has_key(o,k){o[k]}

getValuesOrAll(o,field) =  expr
{
	values = split(o[field],"|")
	expr = [g| g = concat("",["^",values[x],"$"])]

} else = [".*"]


default isSchemaOwner(catalog,schema) = false
isSchemaOwner(catalog,schema){
    can_access_catalog(catalog,"ALL")
	filter_schema_rules(catalog,schema)[0].owner == true
}

filter_schema_rules(catalog,schema) = rules{
    rules=[ r| r = schema_rules[i];
    	regex.match(getValuesOrAll(schema_rules[i],"catalog")[_],catalog)
        regex.match(getValuesOrAll(schema_rules[i],"schema")[_],schema)
        regex.match(getValuesOrAll(schema_rules[i],"user")[_],input.context.identity.user)
        equalsGroupOrMissing(schema_rules[i],input.context.identity.groups[j])
    ]
}

table_allowed(catalog,schema,table){
    isSchemaOwner(catalog,schema)
}

default table_allowed(catalog,schema,table) = false
table_allowed(catalog,schema,table){
    can_access_catalog(catalog,"READ_ONLY")
    rule_to_apply := filter_table_rules(catalog,schema,table)[0]
   	regex.match(getValuesOrAll(rule_to_apply,"catalog")[_],catalog)
    regex.match(getValuesOrAll(rule_to_apply,"user")[_],input.context.identity.user)
    matchGroups(getValuesOrAll(rule_to_apply,"group"),input.context.identity.groups)
    regex.match(getValuesOrAll(rule_to_apply,"schema")[_],schema)
    regex.match(getValuesOrAll(rule_to_apply,"table")[_],table)
    count(rule_to_apply.privileges) > 0
}


filter_table_rules(catalog,schema,table) = rules{
    rules= [ r| r = table_rules[i];
    	regex.match(getValuesOrAll(r,"catalog")[_],catalog)
	    regex.match(getValuesOrAll(r,"user")[_],input.context.identity.user)
        matchGroups(getValuesOrAll(r,"group"),input.context.identity.groups)
    	regex.match(getValuesOrAll(r,"schema")[_],schema)
   	 	regex.match(getValuesOrAll(r,"table")[_],table)
    ]
}

orEmptyArray(array) = result
{
	result = array
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
