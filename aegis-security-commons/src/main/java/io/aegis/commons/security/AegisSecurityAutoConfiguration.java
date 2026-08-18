package io.aegis.commons.security;

import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.audit.CompositeAuditEventPublisher;
import io.aegis.commons.audit.KafkaAuditEventPublisher;
import io.aegis.commons.audit.LoggingAuditEventPublisher;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.kafka.core.KafkaTemplate;

/**
 * Wires the shared audit pipeline into any service that depends on this library.
 *
 * <p>The event flow is CloudTrail-shaped: every security-relevant action across the platform is
 * published through one {@link AuditEventPublisher}, which fans out to
 * <ul>
 *   <li>a structured {@code AUDIT} log — always on, the durable floor; and</li>
 *   <li>a Kafka topic — the streamed forensic backbone a central sink consumes into an append-only
 *       store and a customer SIEM — <em>when Kafka is configured</em>
 *       ({@code spring.kafka.bootstrap-servers} set and {@code KafkaTemplate} on the classpath).</li>
 * </ul>
 * With Kafka unconfigured (local dev, unit tests) the publisher is logging-only, so nothing depends
 * on a broker just to boot. A service can still fully override the {@code auditEventPublisher} bean.
 */
@AutoConfiguration
public class AegisSecurityAutoConfiguration {

    /** The always-on log floor. Named so the composite can compose it explicitly. */
    @Bean
    @ConditionalOnMissingBean(LoggingAuditEventPublisher.class)
    public LoggingAuditEventPublisher loggingAuditEventPublisher() {
        return new LoggingAuditEventPublisher();
    }

    /**
     * The Kafka streaming publisher — created only when a broker is actually configured. Boot's
     * {@code KafkaAutoConfiguration} supplies the {@code KafkaTemplate} when
     * {@code spring.kafka.bootstrap-servers} is set; gating on that property keeps every service that
     * has <em>not</em> opted into Kafka from trying to reach a default localhost broker.
     */
    @Bean
    @ConditionalOnClass(KafkaTemplate.class)
    @ConditionalOnProperty(name = "spring.kafka.bootstrap-servers")
    @ConditionalOnMissingBean(KafkaAuditEventPublisher.class)
    public KafkaAuditEventPublisher kafkaAuditEventPublisher(
            KafkaTemplate<String, String> kafkaTemplate,
            @Value("${aegis.audit.kafka.topic:aegis.audit.events}") String topic) {
        return new KafkaAuditEventPublisher(kafkaTemplate, topic);
    }

    /**
     * The publisher injected everywhere: the log floor plus the Kafka stream when present. A service
     * that defines its own {@code auditEventPublisher} bean overrides this entirely.
     */
    @Bean
    @org.springframework.context.annotation.Primary
    @ConditionalOnMissingBean(name = "auditEventPublisher")
    public AuditEventPublisher auditEventPublisher(
            LoggingAuditEventPublisher logging,
            ObjectProvider<KafkaAuditEventPublisher> kafka) {
        List<AuditEventPublisher> delegates = new ArrayList<>();
        delegates.add(logging); // first — the durable floor is always written before streaming
        KafkaAuditEventPublisher kafkaPublisher = kafka.getIfAvailable();
        if (kafkaPublisher != null) {
            delegates.add(kafkaPublisher);
        }
        return delegates.size() == 1 ? logging : new CompositeAuditEventPublisher(delegates);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationAuditListener authenticationAuditListener(AuditEventPublisher publisher) {
        return new AuthenticationAuditListener(publisher);
    }

    /** One-call, never-throwing helper services use to emit domain events onto the audit trail. */
    @Bean
    @ConditionalOnMissingBean
    public io.aegis.commons.audit.AuditRecorder auditRecorder(AuditEventPublisher publisher) {
        return new io.aegis.commons.audit.AuditRecorder(publisher);
    }
}
