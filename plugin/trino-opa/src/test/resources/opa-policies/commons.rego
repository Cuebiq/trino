package io.trino.spi.security.SystemAccessControl


schema_rules = data.rules.schemas {data.rules.schemas} else = [{"owner": true}]
catalog_rules = data.rules.catalogs { data.rules.catalogs } else = [{"catalog": ".*"}]
table_rules = data.rules.tables

default_column_rules = [] #[{ "name":".*","allow" : true}]

isSchemaOwner(catalog,schema){
    can_access_catalog(catalog,"ALL")
	filter_schema_rules(catalog,schema)[0].owner == true
}
else = false

filter_schema_rules(catalog,schema) = rules{
    rules=[ r| r = schema_rules[i];
        match(schema_rules[i],"catalog",catalog)
        match(schema_rules[i],"schema",schema)
        match(schema_rules[i],"user",input.context.identity.user)
        matchAnyInArray(schema_rules[i],"group",input.context.identity.groups)
    ]
}

table_allowed(catalog,schema,table){
     isSchemaOwner(catalog,schema)
}

table_allowed(catalog,schema,table) = false{
    not can_access_catalog(catalog,"READ_ONLY")
} else = true {
    can_access_catalog(catalog,"READ_ONLY")
    schema == "information_schema"
}else = true {
    can_access_catalog(catalog,"READ_ONLY")
    rule_to_apply := filter_table_rules(catalog,schema,table)[0]
    count(rule_to_apply.privileges) > 0
}else = false



filter_table_rules(catalog,schema,table) = rules{
    rules= [ r| r = table_rules[i];
         match(r,"catalog",catalog)
         match(r,"user",input.context.identity.user)
         matchAnyInArray(r,"group",input.context.identity.groups)
         match(r,"schema",schema)
         match(r,"table",table)
    ]
}


all_columns_allowed(columns, table_rule)
{
	count({x | columns[x]; not column_allowed(columns[x],object.get(table_rule,"columns",[]))}) == 0
}

all_columns_allowed(columns, table_rule)
{
	count(columns) == 0
}


default column_allowed(column, column_rules) = false
column_allowed(column, column_rules){
    match(column_rules[i],"name",column)
    object.get(column_rules[i],"allow",true)
}

column_allowed(column, column_rules)
{
	count({x|column_rules[x];match(column_rules[x],"name",column)}) == 0
}

has_privileges(privileges, requested)
{
	privileges[_] == requested[_]
}else = false
