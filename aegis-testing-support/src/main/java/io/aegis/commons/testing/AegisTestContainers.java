package io.aegis.commons.testing;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Reusable Testcontainers wiring for integration tests. Import into a {@code @SpringBootTest} with
 * {@code @Import(AegisTestContainers.class)}; {@link ServiceConnection} auto-maps the container to
 * the datasource/redis connection details — no {@code @DynamicPropertySource} boilerplate per test.
 *
 * <p>Pin the same image tags used in production compose so tests exercise the real engine version.
 */
@TestConfiguration(proxyBeanMethods = false)
public class AegisTestContainers {

    public static final DockerImageName POSTGRES_IMAGE = DockerImageName.parse("postgres:16-alpine");
    public static final DockerImageName REDIS_IMAGE = DockerImageName.parse("redis:7-alpine");

    @Bean
    @ServiceConnection
    public PostgreSQLContainer<?> postgresContainer() {
        return new PostgreSQLContainer<>(POSTGRES_IMAGE)
                .withDatabaseName("aegis")
                .withReuse(true);
    }

    @Bean
    @ServiceConnection(name = "redis")
    public GenericContainer<?> redisContainer() {
        return new GenericContainer<>(REDIS_IMAGE)
                .withExposedPorts(6379)
                .withReuse(true);
    }
}
