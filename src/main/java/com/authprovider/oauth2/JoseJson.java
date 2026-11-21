package com.authprovider.oauth2;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Strict JSON handling for JOSE headers and JWT claims sets: duplicate member names are rejected
 * (RFC 7515 section 4, RFC 7519 section 4), as are trailing tokens and non-standard JSON extensions.
 */
public final class JoseJson {

    private static final ObjectMapper MAPPER = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .disable(JsonReadFeature.ALLOW_JAVA_COMMENTS, JsonReadFeature.ALLOW_SINGLE_QUOTES,
                    JsonReadFeature.ALLOW_UNQUOTED_FIELD_NAMES, JsonReadFeature.ALLOW_NON_NUMERIC_NUMBERS)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .disable(JsonParser.Feature.AUTO_CLOSE_SOURCE)
            .build();

    private JoseJson() {
    }

    public static byte[] serialize(Map<String, ?> members) {
        try {
            return MAPPER.writeValueAsBytes(members);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unable to serialize JOSE object", e);
        }
    }

    /**
     * Parses a UTF-8 JSON object.
     *
     * @throws IllegalArgumentException when the input is not a single well-formed JSON object
     */
    public static JsonNode parseObject(byte[] utf8) {
        try {
            String text = StandardCharsets.UTF_8.newDecoder()
                    .decode(java.nio.ByteBuffer.wrap(utf8))
                    .toString();
            JsonNode node = MAPPER.readTree(text);
            if (node == null || !node.isObject()) {
                throw new IllegalArgumentException("JSON object expected");
            }
            return node;
        } catch (IOException e) {
            throw new IllegalArgumentException("Malformed JSON", e);
        }
    }
}
