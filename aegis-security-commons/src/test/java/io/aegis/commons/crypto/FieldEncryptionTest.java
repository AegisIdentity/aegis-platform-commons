package io.aegis.commons.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * The at-rest encryption contract. Each rule that protects data ships with the negative test that
 * proves the rule is actually enforced — a wrong key, a tampered ciphertext, or a truncated blob
 * must fail loudly rather than yield attacker-influenced plaintext.
 */
class FieldEncryptionTest {

    private static final String KEY_A = Base64.getEncoder()
            .encodeToString("0123456789abcdef0123456789abcdef".getBytes());
    private static final String KEY_B = Base64.getEncoder()
            .encodeToString("fedcba9876543210fedcba9876543210".getBytes());

    private final FieldEncryption enc = FieldEncryption.fromBase64Key(KEY_A);

    @Test
    void round_trips_a_value() {
        String secret = "a-tenant-signing-key-blob";
        String stored = enc.encrypt(secret);

        assertThat(stored).startsWith("v1:");
        assertThat(stored).doesNotContain(secret); // the plaintext must not survive in the stored form
        assertThat(enc.decrypt(stored)).isEqualTo(secret);
    }

    @Test
    void encrypting_the_same_value_twice_yields_different_ciphertext() {
        // A fresh random IV per value: identical secrets must not be linkable in the database.
        assertThat(enc.encrypt("same")).isNotEqualTo(enc.encrypt("same"));
    }

    @Test
    void a_value_encrypted_under_another_key_is_rejected() {
        String stored = FieldEncryption.fromBase64Key(KEY_B).encrypt("secret");

        assertThatThrownBy(() -> enc.decrypt(stored))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("field decryption failed");
    }

    @Test
    void a_tampered_ciphertext_is_rejected_rather_than_silently_decrypted() {
        String stored = enc.encrypt("secret");
        // Flip a character in the base64 body — GCM's tag must catch it.
        char[] chars = stored.toCharArray();
        chars[chars.length - 2] = (chars[chars.length - 2] == 'A') ? 'B' : 'A';
        String tampered = new String(chars);

        assertThatThrownBy(() -> enc.decrypt(tampered)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void a_truncated_ciphertext_is_rejected() {
        assertThatThrownBy(() -> enc.decrypt("v1:" + Base64.getEncoder().encodeToString(new byte[4])))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void legacy_plaintext_rows_are_returned_as_is_so_existing_data_keeps_working() {
        assertThat(enc.decrypt("legacy-plaintext")).isEqualTo("legacy-plaintext");
        assertThat(FieldEncryption.isEncrypted("legacy-plaintext")).isFalse();
        assertThat(FieldEncryption.isEncrypted(enc.encrypt("x"))).isTrue();
    }

    @Test
    void null_passes_through_both_directions() {
        assertThat(enc.encrypt(null)).isNull();
        assertThat(enc.decrypt(null)).isNull();
    }

    @Test
    void a_key_of_the_wrong_length_is_refused_at_construction() {
        assertThatThrownBy(() -> new FieldEncryption("too-short".getBytes()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
        assertThatThrownBy(() -> FieldEncryption.fromBase64Key("   "))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> FieldEncryption.fromBase64Key("not-base64!!!"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void the_constructor_defensively_copies_so_zeroing_the_callers_array_cannot_break_it() {
        byte[] raw = "0123456789abcdef0123456789abcdef".getBytes();
        FieldEncryption fe = new FieldEncryption(raw);
        java.util.Arrays.fill(raw, (byte) 0); // caller wipes its copy, as it should

        assertThat(fe.decrypt(fe.encrypt("still-works"))).isEqualTo("still-works");
    }
}
