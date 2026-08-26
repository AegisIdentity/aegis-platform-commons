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

    @Test
    void callAs_returns_a_value_and_restores_the_previous_tenant() {
        TenantContext.set(TenantId.of("outer"));

        String seen = TenantContext.callAs(TenantId.of("inner"),
                () -> TenantContext.currentOrThrow().value());

        assertThat(seen).isEqualTo("inner");
        assertThat(TenantContext.currentOrThrow().value()).isEqualTo("outer");
    }

    @Test
    void callAs_clears_the_binding_when_there_was_none_before() {
        TenantContext.callAs(TenantId.of("inner"), () -> "x");
        assertThat(TenantContext.isSet()).isFalse();
    }

    @Test
    void callAs_restores_the_previous_tenant_even_when_the_action_throws() {
        // A leaked binding on a pooled thread is a cross-tenant leak, so the restore has to survive
        // an exception — which is exactly the case a naive set/call/clear at a call site misses.
        TenantContext.set(TenantId.of("outer"));

        assertThatThrownBy(() -> TenantContext.callAs(TenantId.of("inner"), () -> {
            throw new IllegalStateException("boom");
        })).isInstanceOf(IllegalStateException.class);

        assertThat(TenantContext.currentOrThrow().value()).isEqualTo("outer");
    }
}
