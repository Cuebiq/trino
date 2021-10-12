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
   catalogs = "tpch"
   catalogs = "jmx"
}

default getColumnMask = []


getRowFilter =  {
	 "identity": input.context.identity.user,
     "catalog": input.tableName.catalog,
     "schema": input.tableName.schemaTable.schema,
     "expression": concat("",["nationkey in(",filterNations[_],")"])
}{
	true
}

roles = ["20","21","22"]# input.context.identity.user_roles

filterNations[nations]{
	nations = concat(",", roles)
}
