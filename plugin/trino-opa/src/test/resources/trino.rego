package io.trino.spi.security.SystemAccessControl

inputjson := input

default checkCanSetUser = false
#deprecated
checkCanSetUser {
    checkCanImpersonateUser
}

default checkCanImpersonateUser = false

checkCanImpersonateUser = true {
    input.principal.name == "admin"
}
checkCanImpersonateUser {
    input.principal.name == input.userName
}


filterCatalogs[catalogs]{
   catalogs = ["tpch","jmx"][_]
}

checkCanAccessCatalog[exception]{
    not allowCatalog
    exception = concat(" ",["cannot access to catalog",input.catalogName])
}

default checkCanShowTables = false

checkCanShowTables {
    input.schema.catalogName = "tpch"
}

allowCatalog{
    filterCatalogs[_] = input.catalogName
}


getColumnMask =  {
	 "identity": input.context.identity.user,
     "catalog": input.tableName.catalog,
     "schema": input.tableName.schemaTable.schema,
     "expression": data.rules[i].expression
}{
    some i
	input.tableName.catalog = data.rules[i].catalog
	input.tableName.schemaTable.schema = data.rules[i].schema
	input.tableName.schemaTable.table = data.rules[i].table
	input.columnName = data.rules[i].column
}

getRowFilter =  {
	 "identity": input.context.identity.user,
     "catalog": input.tableName.catalog,
     "schema": input.tableName.schemaTable.schema,
     "expression": concat("",["nationkey in(",filterNations[_],")"])
}{
	input.tableName.catalog = "tpch"
	input.tableName.schemaTable.schema = "sf1"
	input.tableName.schemaTable.table = "customer"
}

roles = ["20","21","22"]# input.context.identity.user_roles

filterNations[nations]{
	nations = concat(",", roles)
}
