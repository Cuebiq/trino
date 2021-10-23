package io.trino.spi.security.SystemAccessControl

schema_rules = data.rules.schemas {data.rules.schemas} else = [{"owner": true}]

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

