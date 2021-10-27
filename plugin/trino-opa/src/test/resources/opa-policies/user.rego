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

inpersonation_rules = data.rules.impersonation {  data.rules.impersonation } else = []


#deprecated always return true use checkCanImpersonateUser and mapping_user
checkCanSetUser = true

default checkCanImpersonateUser = false
checkCanImpersonateUser{
    principalName := input.context.identity.user
    user := input.userName
    object.get(filtered_impersonation_rules(principalName,user)[0],"allow",true)
}

filtered_impersonation_rules(principal,user) = [ r| r = inpersonation_rules[x];
    match(r,"original_user",principal)
    match(r,"new_user",user)
]



