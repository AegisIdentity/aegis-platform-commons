package io.aegis.commons.agent;

import java.util.Map;
import java.util.TreeMap;

/**
 * A tool as the platform models it — protocol-agnostic (ADR-0011). MCP, A2A skills and any future
 * protocol all reduce to this shape via an adapter.
 *
 * <p>The split between semantic and cosmetic fields is the security-bearing decision. Semantic
 * fields instruct the model and are covered by {@link #definitionHash()}; cosmetic fields decorate a
 * UI and are not. Classifying a field wrongly is a bug in either direction: too narrow and a rug
 * pull slips through, too wide and every icon change forces a re-consent.
 *
 * @param serverId       which server offers the tool
 * @param toolName       the tool's invocable name
 * @param description    natural-language description — <b>semantic</b>, because this is what the
 *                       model reads and acts on
 * @param inputSchema    JSON Schema for arguments — <b>semantic</b>
 * @param cosmetic       display-only fields, excluded from the hash
 * @param semanticExtras any other meaning-bearing fields an adapter could not map onto the fields
 *                       above. Included in the hash so an unrecognized field fails <em>closed</em>.
 */
public record ToolDescriptor(
        String serverId,
        String toolName,
        String description,
        String inputSchema,
        Map<String, String> cosmetic,
        Map<String, String> semanticExtras) {

    public ToolDescriptor {
        if (serverId == null || serverId.isBlank()) {
            throw new IllegalArgumentException("serverId is required");
        }
        if (toolName == null || toolName.isBlank()) {
            throw new IllegalArgumentException("toolName is required");
        }
        description = description == null ? "" : description;
        inputSchema = inputSchema == null ? "" : inputSchema;
        cosmetic = cosmetic == null ? Map.of() : Map.copyOf(cosmetic);
        semanticExtras = semanticExtras == null ? Map.of() : Map.copyOf(semanticExtras);
    }

    /** Convenience overload for tools with no unmapped semantic fields. */
    public ToolDescriptor(String serverId, String toolName, String description, String inputSchema,
                          Map<String, String> cosmetic) {
        this(serverId, toolName, description, inputSchema, cosmetic, Map.of());
    }

    /**
     * SHA-256 over the canonical semantic form. Stable against key ordering and whitespace,
     * sensitive to any change in what the tool tells the model to do.
     */
    public String definitionHash() {
        StringBuilder canonical = new StringBuilder()
                .append("name=").append(toolName)
                .append("\ndescription=").append(description)
                .append("\ninputSchema=").append(CanonicalJson.canonicalize(inputSchema));
        // TreeMap so extras contribute in a deterministic order regardless of adapter iteration.
        new TreeMap<>(semanticExtras)
                .forEach((k, v) -> canonical.append('\n').append(k).append('=').append(v));
        return CanonicalJson.sha256Hex(canonical.toString());
    }

    /**
     * SHA-256 over the <em>cosmetic</em> fields.
     *
     * <p>{@link #definitionHash()} deliberately ignores these, which means it cannot tell a retitled
     * tool from an unchanged one. Anything that needs to detect display-only drift needs this
     * separate fingerprint — it lives here beside its counterpart rather than being re-derived,
     * inconsistently, by each caller.
     */
    public String cosmeticHash() {
        StringBuilder canonical = new StringBuilder();
        new TreeMap<>(cosmetic)   // TreeMap: map iteration order must not change the hash
                .forEach((k, v) -> canonical.append(k).append('=').append(v).append('\n'));
        return CanonicalJson.sha256Hex(canonical.toString());
    }

    public ToolIdentity identity() {
        return new ToolIdentity(serverId, toolName, definitionHash());
    }
}
