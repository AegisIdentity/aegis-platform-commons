package io.aegis.commons.agent.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import io.aegis.commons.agent.CanonicalJson;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies A2A Agent Card signatures against a per-tenant trust store.
 *
 * <p>A2A advertises capabilities through Agent Cards but <b>leaves card verification entirely to
 * implementers</b> — it does not mandate how a card is proven authentic. Closing that gap is an
 * identity platform's job, and until this class existed the adapter simply believed a
 * caller-supplied boolean, which is not verification at all.
 *
 * <p>Per the A2A specification an {@code AgentCardSignature} is an RFC 7515 JWS in JSON
 * serialization, and the signatures live <em>inside</em> the card. The signed payload is therefore
 * the card <b>with its {@code signatures} field removed</b>.
 *
 * <p><b>Interop caveat, stated because it will bite someone.</b> Because the payload is derived from
 * the document rather than carried alongside it, both signer and verifier must serialize it
 * identically. This implementation canonicalizes (sorted keys, no insignificant whitespace) before
 * hashing. A signer that canonicalizes differently will produce signatures this rejects — the failure
 * looks like tampering, which is a confusing thing to debug. Any future interop work should start
 * here.
 */
public class A2aCardVerifier {

    public static final String PROTOCOL = "a2a";

    private static final Logger log = LoggerFactory.getLogger(A2aCardVerifier.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AgentCardTrustStore trustStore;

    public A2aCardVerifier(AgentCardTrustStore trustStore) {
        this.trustStore = trustStore;
    }

    public CardVerification verify(String tenantId, String cardJson) {
        ObjectNode card;
        try {
            JsonNode parsed = MAPPER.readTree(cardJson);
            if (!(parsed instanceof ObjectNode object)) {
                return CardVerification.MALFORMED;
            }
            card = object;
        } catch (Exception e) {
            return CardVerification.MALFORMED;
        }

        JsonNode signatures = card.get("signatures");
        if (signatures == null || !signatures.isArray() || signatures.isEmpty()) {
            return CardVerification.NO_SIGNATURE;
        }

        // The payload is the card WITHOUT its signatures — they cannot cover themselves.
        ObjectNode payloadNode = card.deepCopy();
        payloadNode.remove("signatures");
        String payload = CanonicalJson.canonicalize(payloadNode.toString());

        List<JWK> trusted = trustStore.trustedKeys(tenantId);

        CardVerification worst = CardVerification.MALFORMED;
        for (JsonNode signature : signatures) {
            CardVerification result = verifyOne(signature, payload, trusted);
            if (result == CardVerification.VERIFIED) {
                return CardVerification.VERIFIED;   // one good signature is enough
            }
            worst = moreInformative(worst, result);
        }
        return worst;
    }

    private CardVerification verifyOne(JsonNode signature, String payload, List<JWK> trusted) {
        JsonNode protectedHeader = signature.get("protected");
        JsonNode signatureValue = signature.get("signature");
        if (protectedHeader == null || signatureValue == null) {
            return CardVerification.MALFORMED;
        }

        JWSHeader header;
        try {
            header = JWSHeader.parse(new Base64URL(protectedHeader.asText()));
        } catch (Exception e) {
            return CardVerification.MALFORMED;
        }

        String signingInput = protectedHeader.asText() + "." + Base64URL.encode(payload);
        Base64URL signatureBytes = new Base64URL(signatureValue.asText());

        boolean sawMatchingKey = false;
        for (JWK candidate : trusted) {
            if (header.getKeyID() != null && candidate.getKeyID() != null
                    && !header.getKeyID().equals(candidate.getKeyID())) {
                continue;
            }
            sawMatchingKey = true;
            try {
                JWSVerifier verifier = verifierFor(candidate);
                if (verifier != null && verifier.verify(header,
                        signingInput.getBytes(StandardCharsets.US_ASCII), signatureBytes)) {
                    return CardVerification.VERIFIED;
                }
            } catch (Exception e) {
                log.debug("a2a_card_verify_failed kid={}: {}", header.getKeyID(), e.toString());
            }
        }

        // A key we trust was found but the signature did not match → the card was altered.
        // No trusted key matched at all → the signer is someone we do not trust.
        return sawMatchingKey ? CardVerification.BAD_SIGNATURE : CardVerification.UNTRUSTED_KEY;
    }

    private static JWSVerifier verifierFor(JWK jwk) throws Exception {
        if (jwk instanceof ECKey ec) {
            return new ECDSAVerifier(ec.toPublicJWK());
        }
        if (jwk instanceof RSAKey rsa) {
            return new RSASSAVerifier(rsa.toPublicJWK());
        }
        return null;   // unsupported key type — treated as "did not verify", never as success
    }

    /** Prefer the outcome that tells an operator most: tampering outranks unknown-signer. */
    private static CardVerification moreInformative(CardVerification current, CardVerification candidate) {
        if (candidate == CardVerification.BAD_SIGNATURE) {
            return CardVerification.BAD_SIGNATURE;
        }
        if (current == CardVerification.MALFORMED) {
            return candidate;
        }
        return current;
    }
}
