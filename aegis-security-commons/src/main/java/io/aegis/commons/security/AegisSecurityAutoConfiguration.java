package io.aegis.commons.security;

import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.audit.LoggingAuditEventPublisher;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Wires the shared audit + auth-event bridge into any service that depends on this library, so audit
 * logging is on by default and consistent. A service can override the {@link AuditEventPublisher}
 * bean (e.g. with a Kafka/SIEM adapter) and this backs off.
 */
@AutoConfiguration
public class AegisSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(AuditEventPublisher.class)
    public AuditEventPublisher auditEventPublisher() {
        return new LoggingAuditEventPublisher();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationAuditListener authenticationAuditListener(AuditEventPublisher publisher) {
        return new AuthenticationAuditListener(publisher);
    }
}
