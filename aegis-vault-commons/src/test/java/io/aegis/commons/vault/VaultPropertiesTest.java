package io.aegis.commons.vault;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Token resolution.
 *
 * <p>A file-sourced token is the normal production shape, not a convenience: Kubernetes projects
 * secrets as files, and the Vault Agent writes its renewed token to a sink file. Putting a
 * long-lived token in an environment variable is the pattern to avoid — it leaks into `docker
 * inspect`, process listings and crash dumps.
 */
class VaultPropertiesTest {

    @Test
    void a_token_file_is_preferred_over_an_inline_token(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("token");
        Files.writeString(file, "hvs.from-file");

        VaultProperties properties = new VaultProperties(true, "http://v:8200", VaultIsolation.PATH,
                "aegis", "hvs.inline", file.toString(), Duration.ofSeconds(3));

        assertThat(properties.resolvedToken()).isEqualTo("hvs.from-file");
    }

    @Test
    void surrounding_whitespace_in_the_file_is_trimmed(@TempDir Path dir) throws IOException {
        // A token written by a shell redirect almost always carries a trailing newline, and Vault
        // rejects the request with a bare 403 that says nothing about why.
        Path file = dir.resolve("token");
        Files.writeString(file, "  hvs.padded\n");

        VaultProperties properties = new VaultProperties(true, "http://v:8200", VaultIsolation.PATH,
                "aegis", null, file.toString(), Duration.ofSeconds(3));

        assertThat(properties.resolvedToken()).isEqualTo("hvs.padded");
    }

    @Test
    void falls_back_to_the_inline_token_when_no_file_is_configured() {
        VaultProperties properties = new VaultProperties(true, "http://v:8200", VaultIsolation.PATH,
                "aegis", "hvs.inline", null, Duration.ofSeconds(3));

        assertThat(properties.resolvedToken()).isEqualTo("hvs.inline");
    }

    @Test
    void an_unreadable_token_file_fails_loudly_rather_than_silently_falling_back() {
        // Falling back to an inline token here would mask a misconfigured secret mount and run with
        // the wrong identity — which is far worse than refusing to start.
        VaultProperties properties = new VaultProperties(true, "http://v:8200", VaultIsolation.PATH,
                "aegis", "hvs.inline", "/no/such/path/token", Duration.ofSeconds(3));

        org.assertj.core.api.Assertions.assertThatThrownBy(properties::resolvedToken)
                .isInstanceOf(VaultException.class);
    }

    @Test
    void no_token_at_all_resolves_to_null_rather_than_an_empty_string() {
        // Vault treats an empty X-Vault-Token header differently from an absent one; null lets the
        // client omit the header entirely, which is what an unauthenticated probe should do.
        VaultProperties properties = new VaultProperties(true, "http://v:8200", VaultIsolation.PATH,
                "aegis", null, null, Duration.ofSeconds(3));

        assertThat(properties.resolvedToken()).isNull();
    }
}
