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
}
