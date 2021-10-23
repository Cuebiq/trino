package io.trino.spi.security.SystemAccessControl

system_information_rules = data.rules.system_information {data.rules.system_information} else = []


default checkCanReadSystemInformation = false
checkCanReadSystemInformation = checkCanSystemInformation(input.context.identity.user,"read")

default checkCanWriteSystemInformation = "Cannot write system information"
checkCanWriteSystemInformation = checkCanSystemInformation(input.context.identity.user,"write")


default checkCanSystemInformation(user,requiredAccess) = false
checkCanSystemInformation(user,requiredAccess) = concat(" ",["Cannot", requiredAccess ,"system information"]) {
    count(system_information_rules) == 0
}

checkCanSystemInformation(user,requiredAccess)
{
    filtered_sys_inf_rules(user)[0].allow[_] == requiredAccess
}

filtered_sys_inf_rules(user) = [r| r = system_information_rules[x];
    match(system_information_rules[x],"user", user)
]
