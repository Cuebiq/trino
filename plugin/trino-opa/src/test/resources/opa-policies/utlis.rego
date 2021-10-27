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
