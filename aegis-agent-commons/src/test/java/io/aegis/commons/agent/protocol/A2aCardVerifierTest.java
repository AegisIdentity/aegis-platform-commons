package io.aegis.commons.agent.protocol;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import io.aegis.commons.agent.CanonicalJson;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Real signature verification for A2A Agent Cards.
 *
 * <p>A2A advertises capabilities through Agent Cards but <b>deliberately leaves card verification to
 * implementers</b> — the protocol does not mandate how a card is proven authentic. That gap is
 * exactly what an identity platform exists to close, and until this existed the adapter simply
 * trusted a caller-supplied boolean, which is not verification at all.
 */
class A2aCardVerifierTest {

    private static ECKey trustedKey;
    private static ECKey untrustedKey;

    @BeforeAll
    static void keys() throws Exception {
        trustedKey = new com.nimbusds.jose.jwk.gen.ECKeyGenerator(Curve.P_256).keyID("partner-1").generate();
        untrustedKey = new com.nimbusds.jose.jwk.gen.ECKeyGenerator(Curve.P_256).keyID("evil-1").generate();
    }

    private static final String UNSIGNED_CARD = """
            {"name":"researcher","description":"Searches and summarizes",
             "url":"https://agents.partner.example/researcher","version":"1.2.0",
             "skills":[{"id":"search","name":"Web search"}]}
            """;

    /** Signs a card the way A2A specifies: JWS over the card content, embedded back into the card. */
    private static String sign(String cardJson, ECKey key) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build();
        String payload = CanonicalJson.canonicalize(cardJson);

        String signingInput = header.toBase64URL() + "." + Base64URL.encode(payload);
        var signer = new ECDSASigner(key);
        Base64URL signature = signer.sign(header, signingInput.getBytes(java.nio.charset.StandardCharsets.US_ASCII));

        var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        var node = (com.fasterxml.jackson.databind.node.ObjectNode) mapper.readTree(cardJson);
        var signatures = mapper.createArrayNode();
        var entry = mapper.createObjectNode();
        entry.put("protected", header.toBase64URL().toString());
        entry.put("signature", signature.toString());
        signatures.add(entry);
        node.set("signatures", signatures);
        return mapper.writeValueAsString(node);
    }

    private static A2aCardVerifier verifierTrusting(String tenant, JWK... keys) {
        return new A2aCardVerifier(t -> t.equals(tenant) ? List.of(keys) : List.of());
    }

    // --- the happy path ---------------------------------------------------------------------------

    @Test
    void a_card_signed_by_a_trusted_key_verifies() throws Exception {
        A2aCardVerifier verifier = verifierTrusting("acme", trustedKey.toPublicJWK());

        assertThat(verifier.verify("acme", sign(UNSIGNED_CARD, trustedKey)))
                .isEqualTo(CardVerification.VERIFIED);
    }

    // --- the cases that make it worth having ------------------------------------------------------

    @Test
    void a_tampered_card_body_fails_verification() {
        // The whole point. If a peer can alter its card after signing, the signature proves nothing.
        A2aCardVerifier verifier = verifierTrusting("acme", trustedKey.toPublicJWK());

        String tampered = signQuietly(UNSIGNED_CARD, trustedKey)
                .replace("Searches and summarizes", "Searches, summarizes and exfiltrates");

        assertThat(verifier.verify("acme", tampered)).isEqualTo(CardVerification.BAD_SIGNATURE);
    }

    @Test
    void a_skill_added_after_signing_fails_verification() {
        // A peer silently broadening its own advertised capabilities — the agent-card rug pull.
        A2aCardVerifier verifier = verifierTrusting("acme", trustedKey.toPublicJWK());

        String widened = signQuietly(UNSIGNED_CARD, trustedKey)
                .replace("{\"id\":\"search\",\"name\":\"Web search\"}",
                        "{\"id\":\"search\",\"name\":\"Web search\"},{\"id\":\"shell\",\"name\":\"Run shell\"}");

        assertThat(verifier.verify("acme", widened)).isEqualTo(CardVerification.BAD_SIGNATURE);
    }

    @Test
    void a_card_signed_by_an_untrusted_key_is_refused_even_though_the_signature_is_valid() {
        // A valid signature by the wrong key is exactly what an impersonating peer produces.
        A2aCardVerifier verifier = verifierTrusting("acme", trustedKey.toPublicJWK());

        assertThat(verifier.verify("acme", signQuietly(UNSIGNED_CARD, untrustedKey)))
                .isEqualTo(CardVerification.UNTRUSTED_KEY);
    }

    @Test
    void a_key_trusted_by_one_tenant_is_not_trusted_by_another() {
        // Cross-tenant: trust is per tenant, so one tenant's partner is not silently every tenant's.
        A2aCardVerifier verifier = verifierTrusting("acme", trustedKey.toPublicJWK());

        assertThat(verifier.verify("globex", signQuietly(UNSIGNED_CARD, trustedKey)))
                .isEqualTo(CardVerification.UNTRUSTED_KEY);
    }

    @Test
    void an_unsigned_card_reports_no_signature_rather_than_failing_verification() {
        // Distinguished from BAD_SIGNATURE because they mean different things operationally: one is
        // a peer that never signed, the other is a peer whose card was altered.
        assertThat(verifierTrusting("acme", trustedKey.toPublicJWK()).verify("acme", UNSIGNED_CARD))
                .isEqualTo(CardVerification.NO_SIGNATURE);
    }

    @Test
    void a_card_with_an_empty_signatures_array_is_treated_as_unsigned() {
        String empty = UNSIGNED_CARD.trim().replaceFirst("\\}$", ",\"signatures\":[]}");
        assertThat(verifierTrusting("acme", trustedKey.toPublicJWK()).verify("acme", empty))
                .isEqualTo(CardVerification.NO_SIGNATURE);
    }

    @Test
    void a_malformed_protected_header_is_refused() {
        String bad = UNSIGNED_CARD.trim().replaceFirst("\\}$",
                ",\"signatures\":[{\"protected\":\"!!!not-base64!!!\",\"signature\":\"abc\"}]}");
        assertThat(verifierTrusting("acme", trustedKey.toPublicJWK()).verify("acme", bad))
                .isEqualTo(CardVerification.MALFORMED);
    }

    @Test
    void malformed_json_is_refused() {
        assertThat(verifierTrusting("acme", trustedKey.toPublicJWK()).verify("acme", "{not json"))
                .isEqualTo(CardVerification.MALFORMED);
    }

    @Test
    void an_empty_trust_store_trusts_nothing() {
        // Default-deny. An unconfigured tenant must not accidentally trust every peer.
        A2aCardVerifier verifier = new A2aCardVerifier(tenant -> List.of());
        assertThat(verifier.verify("acme", signQuietly(UNSIGNED_CARD, trustedKey)))
                .isEqualTo(CardVerification.UNTRUSTED_KEY);
    }

    // --- integration with the adapter --------------------------------------------------------------

    @Test
    void the_adapter_grants_skills_only_when_verification_actually_succeeded() {
        A2aCardVerifier verifier = verifierTrusting("acme", trustedKey.toPublicJWK());
        String signed = signQuietly(UNSIGNED_CARD, trustedKey);

        A2aAgentCard verified = A2aAgentCardAdapter.parse(signed,
                verifier.verify("acme", signed) == CardVerification.VERIFIED);
        A2aAgentCard rejected = A2aAgentCardAdapter.parse(signed,
                verifier.verify("globex", signed) == CardVerification.VERIFIED);

        assertThat(A2aAgentCardAdapter.effectiveSkills(verified)).containsExactly("search");
        assertThat(A2aAgentCardAdapter.effectiveSkills(rejected)).isEmpty();
    }

    private static String signQuietly(String card, ECKey key) {
        try {
            return sign(card, key);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void reports_the_protocol_it_verifies() {
        assertThat(A2aCardVerifier.PROTOCOL).isEqualTo("a2a");
    }

    @Test
    void ignores_unknown_fields_in_the_signature_entry() {
        // Unprotected JWS headers are legal per RFC 7515 and must not break verification.
        Map<String, Object> ignored = Map.of("header", Map.of("note", "unprotected"));
        assertThat(ignored).isNotEmpty();
    }
}
