#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

package io.trino.spi.security.SystemAccessControl


getColumnMask = {
    	 "identity" : user,
         "catalog": input.tableName.catalog,
         "schema": input.tableName.schemaTable.schema,
         "expression": expression
    }
{
   catalog := input.tableName.catalog
   schema := input.tableName.schemaTable.schema
   table := input.tableName.schemaTable.table
   column := input.columnName
   input.tableName.schemaTable.schema != "information_schema"
   rule = filter_column_rules(catalog,schema,table,column)[0]
   expression = rule.mask
   user = column_masked_user(rule)
}

filterColumns[cc]{
    catalog := input.table.catalog
    schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
    match(table_rules[i],"catalog",input.table.catalog)
    count({x|x=filter_table_rules(catalog, schema, table)[0].privileges[i]} - {"SELECT","GRANT_SELECT"}) > 0
    cc = input.columns[i]
}

filterColumns[cc]{
	match(table_rules[i],"catalog",input.table.catalog)
    input.table.schemaTable.schema == "information_schema"
    cc = input.columns[i]
}

filterColumns[cc]{
    some i,j
    catalog := input.table.catalog
    schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
    match(table_rules[i],"catalog",input.table.catalog)
    column_allowed(input.columns[j],object.get(filter_table_rules(catalog, schema, table)[0],"columns", default_column_rules))
    cc = input.columns[j]
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
checkCanSelectFromColumns = false {
    not can_access_catalog(input.table.catalog,"READ_ONLY")
} else = true {
    match(table_rules[i],"catalog",input.table.catalog)
    input.table.schemaTable.schema == "information_schema"
} else = true {
    catalog := input.table.catalog
    schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
    rule_to_apply := filter_table_rules(catalog,schema,table)[0]
    all_columns_allowed(object.get(input,"columns",[]), rule_to_apply)
    has_privileges(rule_to_apply.privileges,["SELECT","GRANT_SELECT"])
}else = true {
    catalog := input.table.catalog
    schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
    count(filter_table_rules(catalog,schema,table))==0
    count(input.columns) == 0
}

default checkCanCreateViewWithSelectFromColumns = "default-exception"

checkCanCreateViewWithSelectFromColumns = "" {
    match(table_rules[i],"catalog",input.table.catalog)
    input.table.schemaTable.schema == "information_schema"
}

checkCanCreateViewWithSelectFromColumns = concat(" ",["View owner '",input.context.identity.user,"' cannot create view that selects from",input.table.schemaTable.table])
{
    catalog := input.table.catalog
    schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
    rule_to_apply := filter_table_rules(catalog,schema,table)[0]
    all_columns_allowed(object.get(input,"columns",[]),rule_to_apply)
    not has_privileges(rule_to_apply.privileges,["GRANT_SELECT"])
}

checkCanCreateViewWithSelectFromColumns = ""{
    catalog := input.table.catalog
    schema := input.table.schemaTable.schema
    table := input.table.schemaTable.table
    rule_to_apply := filter_table_rules(catalog,schema,table)[0]
    all_columns_allowed(object.get(input,"columns",[]),rule_to_apply)
    has_privileges(rule_to_apply.privileges,["GRANT_SELECT"])
}



column_masked_user(rule) = user{
    user = rule.mask_environment.user
}
else = input.context.identity.user


filter_column_rules(catalog,schema,table,column) = [c| c = filter_table_rules(catalog,schema,table)[i].columns[j];
	c.name == column
]


default column_rules(rule_to_apply) = []
column_rules(rule_to_apply) = rules {
    rules := object.get(rule_to_apply,"columns",default_column_rules)
}

