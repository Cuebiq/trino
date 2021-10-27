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

query_rules = data.rules.queries{data.rules.queries} else = []


default checkCanExecuteQuery = false
checkCanExecuteQuery = can_access_query(input.context.identity.user,"execute")

default checkCanViewQueryOwnedBy = false
checkCanViewQueryOwnedBy = can_access_query(input.context.identity.user,"view")


default checkCanKillQueryOwnedBy = false
checkCanKillQueryOwnedBy = can_access_query(input.context.identity.user,"kill")

default filterViewQueryOwnedBy = []
filterViewQueryOwnedBy = input.queryOwners{
    count(query_rules) == 0
}
filterViewQueryOwnedBy =input.queryOwners{
    can_access_query(input.context.identity.user,"view")
}


default can_access_query(user,requiredAccess) = false
can_access_query(user,requiredAccess){
    count(query_rules) == 0
}

can_access_query(user,requiredAccess)
{
    filtered_query_rules(user)[0].allow[_] == requiredAccess
}

filtered_query_rules(user) = [r| r = query_rules[x];
    match(query_rules[x],"user", user)
]
