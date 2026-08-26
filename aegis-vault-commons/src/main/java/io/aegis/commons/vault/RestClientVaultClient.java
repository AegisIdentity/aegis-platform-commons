package io.aegis.commons.vault;

import java.util.Map;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

/**
 * {@link VaultClient} over Vault's HTTP API using Spring's {@code RestClient}.
 *
 * <p>Built on {@code RestClient} rather than a Vault SDK: the surface used is three verbs, and
 * avoiding the SDK keeps the dependency footprint (and its CVE surface) small on a component that
 * now sits on the token path.
 *
 * <p><b>Never logs request or response bodies</b> — both routinely contain key material. Errors
 * carry the status code and path only.
 */
public class RestClientVaultClient implements VaultClient {

    private static final String TOKEN_HEADER = "X-Vault-Token";
    private static final String NAMESPACE_HEADER = "X-Vault-Namespace";

    private final RestClient restClient;
    private final String token;

    public RestClientVaultClient(RestClient restClient, String token) {
        this.restClient = restClient;
        this.token = token;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> read(String path, String namespace) {
        try {
            Map<String, Object> body = restClient.get()
                    .uri("/v1/{path}", path)
                    .headers(headers -> applyHeaders(headers, namespace))
                    .retrieve()
                    .onStatus(HttpStatusCode::is4xxClientError, (req, res) -> { /* absent → empty */ })
                    .body(Map.class);
            return body == null ? Map.of() : body;
        } catch (Exception e) {
            throw new VaultException("vault read failed for path " + path, e);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> write(String path, Map<String, Object> data, String namespace) {
        try {
            Map<String, Object> body = restClient.post()
                    .uri("/v1/{path}", path)
                    .contentType(MediaType.APPLICATION_JSON)
                    .headers(headers -> applyHeaders(headers, namespace))
                    .body(data)
                    .retrieve()
                    .body(Map.class);
            return body == null ? Map.of() : body;
        } catch (Exception e) {
            throw new VaultException("vault write failed for path " + path, e);
        }
    }

    @Override
    public void delete(String path, String namespace) {
        try {
            restClient.delete()
                    .uri("/v1/{path}", path)
                    .headers(headers -> applyHeaders(headers, namespace))
                    .retrieve()
                    .toBodilessEntity();
        } catch (Exception e) {
            throw new VaultException("vault delete failed for path " + path, e);
        }
    }

    private void applyHeaders(org.springframework.http.HttpHeaders headers, String namespace) {
        if (token != null && !token.isBlank()) {
            headers.set(TOKEN_HEADER, token);
        }
        if (namespace != null && !namespace.isBlank()) {
            headers.set(NAMESPACE_HEADER, namespace);
        }
    }
}
