package io.aegis.commons.security;

import java.time.Duration;
import java.util.List;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Builds an explicit {@link CorsConfigurationSource} from an allow-list of origins. Refuses the
 * wildcard-{@code *}-with-credentials combination (browsers reject it anyway, and it is the wrong
 * default). Credentials are enabled because the platform's browser flows rely on cookies/headers.
 */
public final class CorsConfigFactory {

    private CorsConfigFactory() {
    }

    public static CorsConfigurationSource fromAllowedOrigins(List<String> allowedOrigins) {
        if (allowedOrigins == null || allowedOrigins.isEmpty()) {
            throw new IllegalArgumentException("at least one allowed origin is required");
        }
        if (allowedOrigins.contains("*")) {
            throw new IllegalArgumentException(
                    "wildcard origin '*' is not allowed with credentials; list explicit origins");
        }
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.copyOf(allowedOrigins));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Correlation-Id",
                "X-XSRF-TOKEN"));
        config.setExposedHeaders(List.of("X-Correlation-Id"));
        config.setAllowCredentials(true);
        config.setMaxAge(Duration.ofHours(1));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
