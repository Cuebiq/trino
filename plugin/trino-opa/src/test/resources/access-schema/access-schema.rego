package io.trino.spi.security.SystemAccessControl


isSchemaOwner(catalog,schema) {
	some i,j
    equalsOrMissing(data.schemas[i],"catalog",catalog)
    equalsOrMissing(data.schemas[i],"schema",schema)
    equalsOrMissing(data.schemas[i],"user",input.context.identity.user)
	equalsGroupOrMissing(data.schemas[i],input.context.identity.groups[j])
    data.schemas[i].owner == true

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

equalsGroupOrMissing(obj, value)
{
	groups = split(obj.group,"|")
	groups[_] == value
} else {
	not has_key(obj,"group")
}

equalsOrMissing(obj, field, value){
	obj[field] == value
} else {
 	not has_key(obj,field)
}

has_key(o,k){o[k]}
