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

system_session_properties_rules  = data.rules.system_session_properties {data.rules.system_session_properties} else = []
catalog_session_properties_rules  = data.rules.catalog_session_properties {data.rules.catalog_session_properties} else = []


default checkCanSetSystemSessionProperty = false
checkCanSetSystemSessionProperty{
    object.get(filtered_sys_session_prop(input.propertyName)[0],"allow",false)
}

checkCanSetSystemSessionProperty{
    count(system_session_properties_rules) == 0
}

default checkCanSetCatalogSessionProperty = false
checkCanSetCatalogSessionProperty{
    object.get(filtered_catalog_session_prop(input.catalogName, input.propertyName)[0],"allow",false)
}

checkCanSetCatalogSessionProperty{
    count(catalog_session_properties_rules) == 0
}


filtered_sys_session_prop(property) = [p|p = system_session_properties_rules[x];
    match(system_session_properties_rules[x],"user", input.context.identity.user)
    match_any_in_array(system_session_properties_rules[x],"group",input.context.identity.groups)
    match(system_session_properties_rules[x],"property", property)
]

filtered_catalog_session_prop(catalog,property) = [p|p = catalog_session_properties_rules[x];
    can_access_catalog(catalog, "READ_ONLY")
    match(catalog_session_properties_rules[x],"user", input.context.identity.user)
    match_any_in_array(catalog_session_properties_rules[x],"group",input.context.identity.groups)
    match(catalog_session_properties_rules[x],"catalog", catalog)
    match(catalog_session_properties_rules[x],"property", property)
]
