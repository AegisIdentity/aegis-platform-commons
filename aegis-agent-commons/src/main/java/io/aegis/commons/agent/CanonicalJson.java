package io.aegis.commons.agent;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;

/**
 * Canonical JSON + digest helpers.
 *
 * <p>Content-addressing a tool definition (ADR-0013) only works if the digest is stable against
 * things that do not change meaning — key ordering and whitespace — while remaining sensitive to
 * things that do. That is exactly what canonicalization buys, and why the hash is taken over a
 * canonical form rather than over the raw bytes a server happened to send.
 *
 * <p>Array order is <b>preserved</b>: in JSON Schema and in tool definitions, order is frequently
 * meaningful (think {@code required}, or an ordered enum), so sorting arrays would erase real
 * differences.
 */
public final class CanonicalJson {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CanonicalJson() {
    }

    /**
     * Parse and re-emit {@code json} with object keys sorted and whitespace removed.
     *
     * @throws IllegalArgumentException if the input is not valid JSON — never silently returns a
     *                                  degraded value, because a tool definition we cannot parse is
     *                                  a tool we must not pin.
     */
    public static String canonicalize(String json) {
        if (json == null || json.isBlank()) {
            return "";
        }
        try {
            return sort(MAPPER.readTree(json)).toString();
        } catch (Exception e) {
            throw new IllegalArgumentException("not valid JSON: " + e.getMessage(), e);
        }
    }

    /** Parse without canonicalizing, failing loudly on malformed input. */
    public static JsonNode parse(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (Exception e) {
            throw new IllegalArgumentException("not valid JSON: " + e.getMessage(), e);
        }
    }

    private static JsonNode sort(JsonNode node) {
        if (node instanceof ObjectNode object) {
            List<String> names = new ArrayList<>();
            for (Iterator<String> it = object.fieldNames(); it.hasNext(); ) {
                names.add(it.next());
            }
            names.sort(String::compareTo);
            ObjectNode sorted = MAPPER.createObjectNode();
            for (String name : names) {
                sorted.set(name, sort(object.get(name)));
            }
            return sorted;
        }
        if (node instanceof ArrayNode array) {
            ArrayNode result = MAPPER.createArrayNode();
            array.forEach(element -> result.add(sort(element)));  // order preserved deliberately
            return result;
        }
        return node;
    }

    /** Lowercase hex SHA-256 of {@code input}. */
    public static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e); // not reachable on any supported JRE
        }
    }
}
