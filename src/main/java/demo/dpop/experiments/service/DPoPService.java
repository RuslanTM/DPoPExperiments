package demo.dpop.experiments.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import demo.dpop.experiments.model.DPoPPayloadDto;
import demo.dpop.experiments.model.DPoPProofRequestDto;
import demo.dpop.experiments.model.DPoPProofResponseDto;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.*;
import org.keycloak.crypto.def.DefaultCryptoProvider;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;

import javax.enterprise.context.ApplicationScoped;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.keycloak.common.util.CertificateUtils.generateV1SelfSignedCertificate;

@ApplicationScoped
public class DPoPService {

    public DPoPProofResponseDto generateDPoPProof(DPoPProofRequestDto request) {
        CryptoIntegration.init(DefaultCryptoProvider.class.getClassLoader());
        KeyPair keyPair = generateKeyPair();
        JWK jwk = generateJwk(keyPair);
        byte[] dPoPProof = generateJWT(request);
        String dPoP = generateJWT(dPoPProof, keyPair, jwk);
        return new DPoPProofResponseDto(dPoP);
    }

    private KeyPair generateKeyPair() {
        try {
            return CryptoIntegration.getProvider().getKeyPairGen(KeyType.RSA).generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

    }

    private JWK generateJwk(KeyPair keyPair) {
        try {
            PublicKey publicKey = keyPair.getPublic();
            List<X509Certificate> certificates = Arrays.asList(generateV1SelfSignedCertificate(keyPair, "Test"), generateV1SelfSignedCertificate(keyPair, "Intermediate"));
            return JWKBuilder.create().kid(KeyUtils.createKeyId(publicKey)).algorithm("RS256").rsa(publicKey, certificates);
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException(ex);
        }
    }

    private byte[] generateJWT(DPoPProofRequestDto request) {
        try {
            return new ObjectMapper().writeValueAsBytes(generatePayload(request));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private String generateJWT(byte[] dPoPProof, KeyPair keyPair, JWK jwk) {
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setKid(KeyUtils.createKeyId(keyPair.getPublic()));
        keyWrapper.setAlgorithm(Algorithm.RS256);
        keyWrapper.setPrivateKey(keyPair.getPrivate());
        keyWrapper.setPublicKey(keyPair.getPublic());
        keyWrapper.setType(keyPair.getPublic().getAlgorithm());
        keyWrapper.setUse(KeyUse.SIG);

        AsymmetricSignatureSignerContext signatureSignerContext = new AsymmetricSignatureSignerContext(keyWrapper);
        return new JWSBuilder().type("dpop+jwt").jwk(jwk).content(dPoPProof).sign(signatureSignerContext);
    }

    private DPoPPayloadDto generatePayload(DPoPProofRequestDto request) {
        DPoPPayloadDto payload = new DPoPPayloadDto();
        payload.setHtu(request.getUrl());
        payload.setHtm(request.getMethod());
        payload.setJti(UUID.randomUUID().toString());
        payload.setIat(Time.currentTime());
        return payload;
    }
}
