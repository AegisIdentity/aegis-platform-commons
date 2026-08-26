package io.aegis.commons.vault;

/** A Vault operation failed. Never carries response bodies, which may contain secret material. */
public class VaultException extends RuntimeException {

    public VaultException(String message) {
        super(message);
    }

    public VaultException(String message, Throwable cause) {
        super(message, cause);
    }
}
