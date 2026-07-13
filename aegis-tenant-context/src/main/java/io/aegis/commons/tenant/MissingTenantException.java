package io.aegis.commons.tenant;

/** Thrown when tenant-scoped work is attempted with no tenant bound to the current context. */
public class MissingTenantException extends RuntimeException {

    public MissingTenantException() {
        super("no tenant bound to the current context");
    }
}
