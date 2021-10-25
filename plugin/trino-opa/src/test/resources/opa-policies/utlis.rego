package io.trino.spi.security.SystemAccessControl


match(rule, field, value)
{
    regex.match(concat("",["^",object.get(rule,field,".*"),"$"]),value)
}

match_any_in_array(rule, field, values)
{
    regex.match(concat("",["^",object.get(rule,field,".*"),"$"]),values[_])
}else{
 	count(values)==0
    regex.match(concat("",["^",object.get(rule,field,".*"),"$"]),"")
}
