package io.aegis.commons.vault;

import io.aegis.commons.audit.AuditEventPublisher;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import java.time.Duration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * Wires Vault when {@code aegis.vault.enabled=true}.
 *
 * <p>Gated on the property so a service can be deployed before its Vault migration lands, and so
 * unit tests never accidentally reach for a broker. This mirrors how the Kafka audit publisher is
 * activated only when {@code spring.kafka.bootstrap-servers} is set.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "aegis.vault", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(VaultProperties.class)
public class VaultAutoConfiguration {

    /**
     * Builds the {@code RestClient} directly rather than injecting a {@code RestClient.Builder}.
     *
     * <p>Boot 4 splits auto-configuration into per-technology modules, so a {@code
     * RestClient.Builder} bean is not necessarily present just because {@code spring-web} is on the
     * classpath — the same split that makes {@code spring-kafka} and {@code flyway-core} inert
     * without their companion modules. Depending on that bean made admin-api-service fail to start
     * with an unhelpful "no qualifying bean" error. Building the client from plain {@code spring-web}
     * types removes the dependency on any Boot autoconfig module, and lets the configured timeout
     * actually be applied — it was previously declared and never used.
     *
     * <p>The timeout matters: Vault sits on the token path, so a stalled Vault must fail fast rather
     * than occupy a request thread until something else gives up.
     */
    @Bean
    @ConditionalOnMissingBean
    public VaultClient vaultClient(VaultProperties properties) {
        Duration timeout = properties.timeout();
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(timeout);
        requestFactory.setReadTimeout(timeout);

        RestClient restClient = RestClient.builder()
                .baseUrl(properties.uri())
                .requestFactory(requestFactory)
                .build();
        return new RestClientVaultClient(restClient, properties.resolvedToken());
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantVaultPaths tenantVaultPaths(VaultProperties properties) {
        return new TenantVaultPaths(properties.mount(), properties.isolation());
    }

    @Bean
    @ConditionalOnMissingBean
    public VaultTransit vaultTransit(VaultClient client, TenantVaultPaths paths,
                                     org.springframework.beans.factory.ObjectProvider<AuditEventPublisher> audit) {
        // ObjectProvider: a service may legitimately have no audit publisher wired yet, and Vault
        // must not fail to start over a missing audit sink.
        return new VaultTransit(client, paths, audit.getIfAvailable(() -> event -> { }));
    }

    @Bean
    @ConditionalOnMissingBean
    public VaultSecrets vaultSecrets(VaultClient client, TenantVaultPaths paths) {
        return new VaultSecrets(client, paths);
    }
}
