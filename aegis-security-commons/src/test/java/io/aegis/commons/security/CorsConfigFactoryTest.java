package io.aegis.commons.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

class CorsConfigFactoryTest {

    @Test
    void builds_config_for_explicit_origins_with_credentials() {
        var source = (UrlBasedCorsConfigurationSource) CorsConfigFactory.fromAllowedOrigins(
                List.of("https://app.acme.com"));

        CorsConfiguration config = source.getCorsConfigurations().get("/**");
        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly("https://app.acme.com");
        assertThat(config.getAllowCredentials()).isTrue();
        assertThat(config.getAllowedMethods()).contains("GET", "POST", "DELETE", "OPTIONS");
    }

    @Test
    void rejects_wildcard_origin_with_credentials() {
        assertThatThrownBy(() -> CorsConfigFactory.fromAllowedOrigins(List.of("*")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("wildcard");
    }

    @Test
    void rejects_empty_origins() {
        assertThatThrownBy(() -> CorsConfigFactory.fromAllowedOrigins(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejects_literal_null_origin() {
        assertThatThrownBy(() -> CorsConfigFactory.fromAllowedOrigins(List.of("null")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null");
    }

    @Test
    void rejects_non_https_origin() {
        assertThatThrownBy(() -> CorsConfigFactory.fromAllowedOrigins(List.of("http://app.acme.com")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("https");
    }

    @Test
    void rejects_http_localhost_by_default() {
        assertThatThrownBy(() -> CorsConfigFactory.fromAllowedOrigins(List.of("http://localhost:5173")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void allows_http_localhost_when_insecure_localhost_enabled() {
        var source = (UrlBasedCorsConfigurationSource) CorsConfigFactory.fromAllowedOrigins(
                List.of("http://localhost:5173"), true);

        CorsConfiguration config = source.getCorsConfigurations().get("/**");
        assertThat(config.getAllowedOrigins()).containsExactly("http://localhost:5173");
        assertThat(config.getAllowCredentials()).isTrue();
    }
}
