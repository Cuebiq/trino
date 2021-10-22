package io.trino.spi.security.SystemAccessControl

schema_rules = data.rules.schemas

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


default checkCanCreateSchema = false
checkCanCreateSchema {
	isSchemaOwner(input.schema.catalogName,input.schema.schemaName)
}

default checkCanDropSchema = false
checkCanDropSchema {
	isSchemaOwner(input.schema.catalogName,input.schema.schemaName)
}

default checkCanRenameSchema = false
checkCanRenameSchema{
   isSchemaOwner(input.schema.catalogName,input.schema.schemaName)
   isSchemaOwner(input.schema.catalogName,input.newSchemaName)
}

default checkCanSetSchemaAuthorization = false
checkCanSetSchemaAuthorization{
    isSchemaOwner(input.schema.catalogName,input.schema.schemaName)
}

default checkCanShowCreateSchema = false
checkCanShowCreateSchema
{
    isSchemaOwner(input.schemaName.catalogName,input.schemaName.schemaName)
}

default checkCanGrantSchemaPrivilege = false
checkCanGrantSchemaPrivilege{
    isSchemaOwner(input.schema.catalogName,input.schema.schemaName)
}

default checkCanRevokeSchemaPrivilege = false
checkCanRevokeSchemaPrivilege{
    isSchemaOwner(input.schema.catalogName,input.schema.schemaName)
}

