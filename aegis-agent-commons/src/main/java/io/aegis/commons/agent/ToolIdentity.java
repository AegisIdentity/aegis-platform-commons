package io.aegis.commons.agent;

/**
 * The addressable identity of a tool: <b>which server</b>, <b>which tool</b>, and <b>which version
 * of its definition</b> (ADR-0013).
 *
 * <p>The definition hash is deliberately <em>not</em> derived from {@code serverId}. Two servers may
 * legitimately publish an identical tool definition — they share a hash but must never share an
 * identity, or an identical-looking tool from an untrusted server would be indistinguishable from
 * the approved one.
 */
public record ToolIdentity(String serverId, String toolName, String definitionHash) {

    private static final String DIGEST_PREFIX = "@sha256:";

    public ToolIdentity {
        if (serverId == null || serverId.isBlank()) {
            throw new IllegalArgumentException("serverId is required");
        }
        if (toolName == null || toolName.isBlank()) {
            throw new IllegalArgumentException("toolName is required");
        }
        if (definitionHash == null || definitionHash.isBlank()) {
            throw new IllegalArgumentException("definitionHash is required");
        }
    }

    /** {@code files-server/read@sha256:9f2c…} — stable, comparable, safe to log. */
    public String toUri() {
        return serverId + "/" + toolName + DIGEST_PREFIX + definitionHash;
    }

    public static ToolIdentity parse(String uri) {
        if (uri == null) {
            throw new IllegalArgumentException("tool identity uri is required");
        }
        int digestAt = uri.indexOf(DIGEST_PREFIX);
        int slashAt = uri.indexOf('/');
        if (digestAt < 0 || slashAt < 0 || slashAt > digestAt) {
            throw new IllegalArgumentException(
                    "malformed tool identity uri, expected server/tool@sha256:hash but got: " + uri);
        }
        return new ToolIdentity(
                uri.substring(0, slashAt),
                uri.substring(slashAt + 1, digestAt),
                uri.substring(digestAt + DIGEST_PREFIX.length()));
    }
}
