package io.trino.plugin.opa;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import io.trino.spi.security.ViewExpression;

import java.io.IOException;
import java.util.Optional;

public class ViewExpressionDeserializer extends StdDeserializer<ViewExpression>
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
            throws IOException, JsonProcessingException
    {
        JsonNode node = p.getCodec().readTree(p);
        return new ViewExpression(
                node.get("identity").asText(),
                Optional.of(node.get("catalog").asText()),
                Optional.of(node.get("schema").asText()),
                node.get("expression").asText());
    }
}
