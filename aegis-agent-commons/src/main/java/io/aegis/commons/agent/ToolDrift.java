package io.aegis.commons.agent;

import java.util.Objects;

/**
 * How an observed tool definition differs from the one that was consented to (ADR-0013).
 *
 * <p>The distinction is the whole point: {@link #SEMANTIC} drift means the tool now instructs the
 * model differently and consent must be re-obtained, while {@link #COSMETIC} drift is a label change
 * that should not interrupt anyone.
 */
public enum ToolDrift {

    /** Byte-for-byte equivalent, semantically and cosmetically. */
    UNCHANGED,

    /** Display-only change. Safe to auto-re-pin when tenant policy allows it. */
    COSMETIC,

    /** The definition the model acts on has changed. Consent is void until re-approved. */
    SEMANTIC;

    /**
     * Classify the difference between a pinned definition and a newly observed one.
     *
     * @throws IllegalArgumentException if the two descriptors are not the same tool. Comparing
     *                                  different tools is a programming error, and returning
     *                                  {@code SEMANTIC} for it would hide the bug behind a
     *                                  plausible-looking verdict.
     */
    public static ToolDrift between(ToolDescriptor pinned, ToolDescriptor observed) {
        Objects.requireNonNull(pinned, "pinned");
        Objects.requireNonNull(observed, "observed");
        if (!pinned.serverId().equals(observed.serverId())
                || !pinned.toolName().equals(observed.toolName())) {
            throw new IllegalArgumentException("cannot compare different tools: "
                    + pinned.serverId() + "/" + pinned.toolName() + " vs "
                    + observed.serverId() + "/" + observed.toolName());
        }
        if (!pinned.definitionHash().equals(observed.definitionHash())) {
            return SEMANTIC;
        }
        return pinned.cosmetic().equals(observed.cosmetic()) ? UNCHANGED : COSMETIC;
    }
}
