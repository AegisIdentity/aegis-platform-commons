package io.aegis.commons.tenant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class TenantContextTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void starts_empty() {
        assertThat(TenantContext.current()).isEmpty();
        assertThat(TenantContext.isSet()).isFalse();
    }

    @Test
    void set_then_current_returns_value() {
        TenantContext.set(TenantId.of("acme"));
        assertThat(TenantContext.current()).contains(TenantId.of("acme"));
        assertThat(TenantContext.isSet()).isTrue();
    }

    @Test
    void currentOrThrow_throws_when_unset() {
        assertThatThrownBy(TenantContext::currentOrThrow).isInstanceOf(MissingTenantException.class);
    }

    @Test
    void clear_removes_binding() {
        TenantContext.set(TenantId.of("acme"));
        TenantContext.clear();
        assertThat(TenantContext.current()).isEmpty();
    }

    @Test
    void set_null_is_rejected() {
        assertThatThrownBy(() -> TenantContext.set(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void runAs_restores_previous_tenant() {
        TenantContext.set(TenantId.of("outer"));
        TenantContext.runAs(TenantId.of("inner"),
                () -> assertThat(TenantContext.currentOrThrow()).isEqualTo(TenantId.of("inner")));
        assertThat(TenantContext.currentOrThrow()).isEqualTo(TenantId.of("outer"));
    }

    @Test
    void runAs_clears_when_no_previous_tenant() {
        TenantContext.runAs(TenantId.of("inner"), () -> { /* work */ });
        assertThat(TenantContext.current()).isEmpty();
    }
}
