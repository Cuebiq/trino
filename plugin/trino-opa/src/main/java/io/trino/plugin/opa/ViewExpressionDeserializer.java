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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import io.trino.spi.security.ViewExpression;

import java.io.IOException;
import java.util.Optional;

public class ViewExpressionDeserializer
        extends StdDeserializer<ViewExpression>
{
    public ViewExpressionDeserializer(Class<?> vc)
    {
        super(vc);
    }

    public ViewExpressionDeserializer(JavaType valueType)
    {
        super(valueType);
    }

    public ViewExpressionDeserializer(StdDeserializer<?> src)
    {
        super(src);
    }

    @Override
    public ViewExpression deserialize(JsonParser p, DeserializationContext ctx)
            throws IOException
    {
        JsonNode node = p.getCodec().readTree(p);
        return new ViewExpression(
                node.get("identity").asText(),
                Optional.of(node.get("catalog").asText()),
                Optional.of(node.get("schema").asText()),
                node.get("expression").asText());
    }
}
