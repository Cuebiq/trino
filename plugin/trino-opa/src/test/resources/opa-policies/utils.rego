package io.trino.spi.security.SystemAccessControl


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
	groups = split(o[field],"|")
	expr = [g| g = concat("",["^",groups[x],"$"])]

} else = [".*"]
