package io.aegis.commons.tenant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TenantIdTest {

    @Test
    void accepts_valid_slug() {
        assertThat(TenantId.of("acme-corp_01").value()).isEqualTo("acme-corp_01");
    }

    @Test
    void value_equality_holds() {
        assertThat(TenantId.of("acme")).isEqualTo(new TenantId("acme"));
        assertThat(TenantId.of("acme")).isNotEqualTo(TenantId.of("other"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "  ", "has space", "bad/slash", "../etc", "with.dot", "emoji😀"})
    void rejects_blank_or_illegal_characters(String bad) {
        assertThatThrownBy(() -> TenantId.of(bad)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejects_null() {
        assertThatThrownBy(() -> TenantId.of(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejects_over_64_chars() {
        assertThatThrownBy(() -> TenantId.of("a".repeat(65)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
