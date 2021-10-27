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

system_information_rules = data.rules.system_information {data.rules.system_information} else = []


default checkCanReadSystemInformation = false
checkCanReadSystemInformation = check_can_system_information(input.context.identity.user,"read")

default checkCanWriteSystemInformation = "Cannot write system information"
checkCanWriteSystemInformation = check_can_system_information(input.context.identity.user,"write")


default check_can_system_information(user,requiredAccess) = false
checkCanSystemInformation(user,requiredAccess) = concat(" ",["Cannot", requiredAccess ,"system information"]) {
    count(system_information_rules) == 0
}

check_can_system_information(user,requiredAccess)
{
    filtered_sys_inf_rules(user)[0].allow[_] == requiredAccess
}

filtered_sys_inf_rules(user) = [r| r = system_information_rules[x];
    match(system_information_rules[x],"user", user)
]



