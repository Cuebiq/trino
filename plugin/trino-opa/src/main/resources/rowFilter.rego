package io.trino.spi.security.SystemAccessControl

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
