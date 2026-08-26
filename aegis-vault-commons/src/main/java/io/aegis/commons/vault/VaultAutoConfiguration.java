package io.aegis.commons.vault;

import io.aegis.commons.audit.AuditEventPublisher;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
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

    @Bean
    @ConditionalOnMissingBean
    public VaultClient vaultClient(VaultProperties properties, RestClient.Builder builder) {
        return new RestClientVaultClient(builder.baseUrl(properties.uri()).build(), properties.token());
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
