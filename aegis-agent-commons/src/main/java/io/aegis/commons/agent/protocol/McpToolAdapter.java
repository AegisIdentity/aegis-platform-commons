package io.aegis.commons.agent.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import io.aegis.commons.agent.CanonicalJson;
import io.aegis.commons.agent.ToolDescriptor;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Translates an MCP tool definition (revision {@code 2026-07-28}) into the protocol-agnostic
 * {@link ToolDescriptor}. Per ADR-0011 this is the only class that knows MCP's field names; nothing
 * downstream does.
 */
public final class McpToolAdapter {

    public static final String PROTOCOL = "mcp";

    /**
     * Display-only fields.
     *
     * <p>This is a <b>deny-list, not an allow-list</b>, and that direction is deliberate. Any field
     * this adapter does not recognize is treated as semantic and therefore folded into the
     * definition hash — so a future MCP revision that adds a field capable of instructing the model
     * causes a re-consent rather than being silently ignored. An allow-list of semantic fields would
     * fail open on exactly the case that matters.
     */
    private static final Set<String> COSMETIC_FIELDS = Set.of("title", "icons", "_meta", "annotations");

    /** Fields this adapter maps onto first-class {@link ToolDescriptor} components. */
    private static final Set<String> MAPPED_FIELDS = Set.of("name", "description", "inputSchema");

    private McpToolAdapter() {
    }

    public static ToolDescriptor toDescriptor(String serverId, String toolJson) {
        JsonNode root = CanonicalJson.parse(toolJson);

        JsonNode name = root.get("name");
        if (name == null || name.asText().isBlank()) {
            throw new IllegalArgumentException("MCP tool definition has no name");
        }

        JsonNode description = root.get("description");
        JsonNode inputSchema = root.get("inputSchema");

        Map<String, String> cosmetic = new LinkedHashMap<>();
        Map<String, String> semanticExtras = new LinkedHashMap<>();
        for (Iterator<String> it = root.fieldNames(); it.hasNext(); ) {
            String field = it.next();
            if (MAPPED_FIELDS.contains(field)) {
                continue;
            }
            String value = render(root.get(field));
            if (COSMETIC_FIELDS.contains(field)) {
                cosmetic.put(field, value);
            } else {
                semanticExtras.put(field, value);
            }
        }

        return new ToolDescriptor(
                serverId,
                name.asText(),
                description == null ? "" : description.asText(),
                inputSchema == null ? "" : inputSchema.toString(),
                cosmetic,
                semanticExtras);
    }

    private static String render(JsonNode node) {
        return node == null ? "" : (node.isTextual() ? node.asText() : CanonicalJson.canonicalize(node.toString()));
    }
}
