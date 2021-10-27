/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.plugin.opa;

import io.trino.spi.security.SystemAccessControl;

import java.lang.reflect.Proxy;

public class OpaSystemAccessControl
        extends Proxy
        implements SystemAccessControl
{
    protected OpaSystemAccessControl(OpaInvocationHandler h)
    {
        super(h);
    }

    public static SystemAccessControl getInstance(OpaConfig config)
    {
        return (SystemAccessControl) OpaSystemAccessControl.newProxyInstance(
                OpaSystemAccessControl.class.getClassLoader(), new Class[] {SystemAccessControl.class}, new OpaInvocationHandler(config));
    }
}
