package io.aegis.commons.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.commons.tenant.TenantContext;
import io.aegis.commons.tenant.TenantId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

class AuditEventTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
        MDC.clear();
    }

    @Test
    void builder_autofills_tenant_correlation_and_time() {
        TenantContext.set(TenantId.of("acme"));
        MDC.put("correlationId", "corr-9");

        AuditEvent event = AuditEvent.of("auth", "login", AuditOutcome.SUCCESS)
                .actor("user-1")
                .build();

        assertThat(event.tenantId()).isEqualTo("acme");
        assertThat(event.correlationId()).isEqualTo("corr-9");
        assertThat(event.actor()).isEqualTo("user-1");
        assertThat(event.at()).isNotNull();
    }

    @Test
    void defaults_actor_to_anonymous() {
        assertThat(AuditEvent.of("auth", "login", AuditOutcome.FAILURE).build().actor())
                .isEqualTo("anonymous");
    }

    @Test
    void attributes_are_immutable_copy() {
        AuditEvent event = AuditEvent.of("authz", "access", AuditOutcome.DENIED)
                .attribute("resource", "/api/v1/users")
                .build();
        assertThat(event.attributes()).containsEntry("resource", "/api/v1/users");
        assertThatThrownBy(() -> event.attributes().put("x", "y"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejects_blank_type_or_action() {
        assertThatThrownBy(() -> AuditEvent.of(" ", "login", AuditOutcome.SUCCESS).build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AuditEvent.of("auth", " ", AuditOutcome.SUCCESS).build())
                .isInstanceOf(IllegalArgumentException.class);
    }
}
