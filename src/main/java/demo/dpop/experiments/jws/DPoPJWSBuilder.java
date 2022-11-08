package demo.dpop.experiments.jws;

import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class DPoPJWSBuilder extends JWSBuilder {

    String type;
    String kid;
    String contentType;
    JWK jwk;
    byte[] contentBytes;

    public DPoPJWSBuilder() {
        super();
    }

    public DPoPJWSBuilder jwk(JWK jwk) {
        this.jwk = jwk;
        return this;
    }

    public DPoPJWSBuilder type(String type) {
        this.type = type;
        super.type(type);
        return this;
    }

    public DPoPJWSBuilder kid(String kid) {
        this.kid = kid;
        super.kid(kid);
        return this;
    }

    public DPoPJWSBuilder contentType(String type) {
        this.contentType = type;
        super.contentType(type);
        return this;
    }

    public EncodingBuilder content(byte[] bytes) {
        this.contentBytes = bytes;
        super.content(bytes);
        return new EncodingBuilder();
    }

    @Override
    protected String encodeHeader(String sigAlgName) {
        StringBuilder builder = new StringBuilder("{");
        builder.append("\"alg\":\"").append(sigAlgName).append("\"");

        if (type != null) builder.append(",\"typ\" : \"").append(type).append("\"");
        if (kid != null) builder.append(",\"kid\" : \"").append(kid).append("\"");
        if (contentType != null) builder.append(",\"cty\":\"").append(contentType).append("\"");
        if (jwk != null) {
            try {
                builder.append(",\"jwk\":").append(JsonSerialization.writeValueAsString(jwk));
            } catch (IOException e) {
                //TODO: CATCH correctly
                throw new RuntimeException(e);
            }
        }
        builder.append("}");
        return Base64Url.encode(builder.toString().getBytes(StandardCharsets.UTF_8));
    }
}
