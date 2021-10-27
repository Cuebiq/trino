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

table_rules = data.rules.tables {data.rules.tables} else = [{"privileges": ["SELECT", "INSERT", "UPDATE", "DELETE", "OWNERSHIP"]}]

getRowFilter =  {
	 "identity": user,
     "catalog": input.tableName.catalog,
     "schema": input.tableName.schemaTable.schema,
     "expression": expression
}{
    catalog := input.tableName.catalog
    schema := input.tableName.schemaTable.schema
    table := input.tableName.schemaTable.table
    input.tableName.schemaTable.schema != "information_schema"
    rule = filter_table_rules(catalog,schema,table)[0]
    expression = rule.filter
    user = filter_masked_user(rule)
}


filterTables[tt]{
    table_allowed(input.catalogName,input.tableNames[i].schema,input.tableNames[i].table)
    tt = input.tableNames[i]
}


default checkCanShowTables = false
checkCanShowTables{
   check_any_schema_access(input.schema.catalogName, input.schema.schemaName)
}

default checkCanInsertIntoTable = false
checkCanInsertIntoTable = check_table_permission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"INSERT")

default checkCanCreateTable = false
checkCanCreateTable = check_table_permission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanDropTable = false
checkCanDropTable = check_table_permission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanGrantTablePrivilege = false
checkCanGrantTablePrivilege = check_table_permission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanRevokeTablePrivilege = false
checkCanRevokeTablePrivilege = check_table_permission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanShowCreateTable = false
checkCanShowCreateTable = check_table_permission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanAddColumn = false
checkCanAddColumn = check_table_permission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanDropColumn = false
checkCanDropColumn = check_table_permission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanRenameColumn = false
checkCanRenameColumn = check_table_permission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanSetTableAuthorization = false
checkCanSetTableAuthorization = check_table_permission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanSetViewAuthorization = false
checkCanSetViewAuthorization = check_table_permission(input.view.catalog,input.view.schemaTable.schema,input.view.schemaTable.table,"OWNERSHIP")

default checkCanSetTableComment = false
checkCanSetTableComment = check_table_permission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")

default checkCanRenameTable = false
checkCanRenameTable{
    check_table_permission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"OWNERSHIP")
    check_table_permission(input.newTable.catalog,input.newTable.schemaTable.schema,input.newTable.schemaTable.table,"OWNERSHIP")
}

default checkCanDeleteFromTable = false
checkCanDeleteFromTable = check_table_permission(input.table.catalog,input.table.schemaTable.schema,input.table.schemaTable.table,"DELETE")


default checkCanDropMaterializedView = false
checkCanDropMaterializedView = check_table_permission(
    input.materializedView.catalog,
    input.materializedView.schemaTable.schema,
    input.materializedView.schemaTable.table,"OWNERSHIP")

default checkCanCreateMaterializedView = false
checkCanCreateMaterializedView = check_table_permission(
    input.materializedView.catalog,
    input.materializedView.schemaTable.schema,
    input.materializedView.schemaTable.table,"OWNERSHIP")

default checkCanRefreshMaterializedView = false
checkCanRefreshMaterializedView = check_table_permission(
    input.materializedView.catalog,
    input.materializedView.schemaTable.schema,
    input.materializedView.schemaTable.table,"UPDATE")

filter_masked_user(rule) = user{
    user = rule.filter_environment.user
}
else = input.context.identity.user

check_table_permission(catalog,schema,table,privilege) = false {
    not can_access_catalog(input.table.catalog,required_catalog_access(privilege))
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
}else = true {
     count(table_rules)==0
}
