pub mod crypto;

#[cfg(test)]
mod tests {
    use super::crypto::*;

    #[test]
    fn test_mlkem_keygen_round_trip() {
        let keypair = generate_response_keypair().unwrap();
        assert_eq!(keypair.public_key.len(), MLKEM_EK_SIZE);
        // secret_key is the 64-byte ML-KEM seed (we reconstruct the DK from it).
        assert_eq!(keypair.secret_key.len(), 64);
    }

    #[test]
    fn test_mlkem_encapsulate_decapsulate_round_trip() {
        // Generate a server keypair, encapsulate against it, decapsulate, shared secrets match.
        let server = generate_response_keypair().unwrap();
        let (ciphertext, shared_secret) =
            encapsulate_against_server_pubkey(&server.public_key).unwrap();
        assert_eq!(ciphertext.len(), MLKEM_CT_SIZE);
        assert_eq!(shared_secret.len(), MLKEM_SHARED_SECRET_SIZE);
        let recovered = decapsulate(&server.secret_key, &ciphertext).unwrap();
        assert_eq!(recovered.as_slice(), shared_secret.as_slice());
    }

    #[test]
    fn test_hkdf_sha256_derives_32_byte_key() {
        // HKDF-SHA256 with salt and info, per the protocol.
        let secret = random_bytes(32);
        let salt = random_bytes(16);
        let info = b"e2e-req-v1";
        let key = hkdf_sha256(&secret, &salt, info).unwrap();
        assert_eq!(key.len(), 32);
        // Same inputs → same output (deterministic).
        let key2 = hkdf_sha256(&secret, &salt, info).unwrap();
        assert_eq!(key, key2);
        // Different info → different output.
        let key3 = hkdf_sha256(&secret, &salt, b"e2e-resp-v1").unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_chacha20poly1305_seal_open_round_trip() {
        let key = random_bytes(32);
        let nonce = random_bytes(12);
        let plaintext = b"hello e2e world";
        let aad = b"";
        let ciphertext = chacha20poly1305_seal(&key, &nonce, plaintext, aad).unwrap();
        // ciphertext includes the 16-byte tag appended.
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
        let recovered = chacha20poly1305_open(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(recovered, plaintext);
        // Wrong key → open fails.
        let wrong_key = random_bytes(32);
        assert!(chacha20poly1305_open(&wrong_key, &nonce, &ciphertext, aad).is_err());
    }

    #[test]
    fn test_gzip_compress_decompress_round_trip() {
        let data = b"{\"model\":\"test\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}";
        let compressed = gzip_compress(data).unwrap();
        assert!(compressed.len() > 0);
        let decompressed = gzip_decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_request_blob_layout_construction_and_parse() {
        // Blob: mlkem_ct(1088) || nonce(12) || ciphertext || tag(16)
        let mlkem_ct = random_bytes(MLKEM_CT_SIZE);
        let nonce = random_bytes(12);
        let payload = b"encrypted payload here";
        let tag = random_bytes(16);
        let blob = build_request_blob(&mlkem_ct, &nonce, payload, &tag);
        assert_eq!(blob.len(), 1088 + 12 + payload.len() + 16);
        let (parsed_ct, parsed_nonce, parsed_payload_tag) = parse_request_blob(&blob).unwrap();
        assert_eq!(parsed_ct, mlkem_ct);
        assert_eq!(parsed_nonce, nonce);
        assert_eq!(parsed_payload_tag, [payload, &tag[..]].concat());
    }

    #[test]
    fn test_request_blob_parse_rejects_too_short() {
        let short = vec![0u8; 1088 + 12]; // missing ciphertext+tag
        assert!(parse_request_blob(&short).is_err());
    }

    #[test]
    fn test_encrypt_request_full_pipeline() {
        // Full pipeline: keygen → encapsulate → HKDF → encrypt
        let server = generate_response_keypair().unwrap();
        let payload = serde_json::json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hi"}],
            "e2e_response_pk": "placeholder"
        });
        let payload_str = serde_json::to_string(&payload).unwrap();
        let (blob, response_sk) =
            encrypt_request(&server.public_key, payload_str.as_bytes()).unwrap();
        // Blob layout: 1088 + 12 + ciphertext + 16
        assert!(blob.len() >= MLKEM_CT_SIZE + 12 + 16);
        let (_, _, ct_with_tag) = parse_request_blob(&blob).unwrap();
        // ct_with_tag should end with 16-byte tag
        assert!(ct_with_tag.len() >= 16);
        assert_eq!(response_sk.len(), 64);
    }

    #[test]
    fn test_encrypt_then_decrypt_request_round_trip() {
        // Encrypt a request, then decrypt the blob → recover the original payload.
        let server = generate_response_keypair().unwrap();
        let original = br#"{"model":"test","messages":[]}"#;
        let (blob, _response_sk) = encrypt_request(&server.public_key, original).unwrap();
        let recovered = decrypt_request_blob(&server.secret_key, &blob).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_decrypt_non_streaming_response_round_trip() {
        // Simulate server-side: build a response blob, then client decrypts it.
        // The server uses the client's response_pk to encapsulate.
        let client_kp = generate_response_keypair().unwrap();
        // Server encapsulates against client's response public key.
        let (mlkem_ct, shared_secret) =
            encapsulate_against_server_pubkey(&client_kp.public_key).unwrap();
        let salt = &mlkem_ct[..16];
        let response_key = hkdf_sha256(&shared_secret, salt, HKDF_INFO_RESPONSE).unwrap();
        let plaintext = br#"{"id":"msg_1","content":[{"type":"text","text":"hi"}]}"#;
        let compressed = gzip_compress(plaintext).unwrap();
        let nonce = random_bytes(12);
        let ciphertext = chacha20poly1305_seal(&response_key, &nonce, &compressed, b"").unwrap();
        let (ct_part, tag_part) = ciphertext.split_at(ciphertext.len() - 16);
        let blob = build_request_blob(&mlkem_ct, &nonce, ct_part, tag_part);
        // Client decrypts.
        let recovered = decrypt_response(&client_kp.secret_key, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_decrypt_streaming_sse_round_trip() {
        // Simulate SSE streaming: e2e_init then e2e chunks.
        let client_kp = generate_response_keypair().unwrap();
        // e2e_init: server encapsulates against client's response_pk.
        let (e2e_init_ct, shared_secret) =
            encapsulate_against_server_pubkey(&client_kp.public_key).unwrap();
        let salt = &e2e_init_ct[..16];
        let stream_key = hkdf_sha256(&shared_secret, salt, HKDF_INFO_STREAM).unwrap();
        // Chunk 1: nonce(12) + ct + tag(16)
        let chunk1_plaintext = b"data: {\"type\":\"message_start\"}\n\n";
        let chunk1_nonce = random_bytes(12);
        let chunk1_ct = chacha20poly1305_seal(&stream_key, &chunk1_nonce, chunk1_plaintext, b"").unwrap();
        let chunk1_blob = [chunk1_nonce.as_slice(), chunk1_ct.as_slice()].concat();
        // Chunk 2
        let chunk2_plaintext = b"data: {\"type\":\"content_block_delta\"}\n\n";
        let chunk2_nonce = random_bytes(12);
        let chunk2_ct = chacha20poly1305_seal(&stream_key, &chunk2_nonce, chunk2_plaintext, b"").unwrap();
        let chunk2_blob = [chunk2_nonce.as_slice(), chunk2_ct.as_slice()].concat();
        // Client decrypts stream.
        let derived_stream_key = decrypt_stream_init(&client_kp.secret_key, &e2e_init_ct).unwrap();
        assert_eq!(derived_stream_key, stream_key);
        let dec1 = decrypt_stream_chunk(&stream_key, &chunk1_blob).unwrap();
        assert_eq!(dec1, chunk1_plaintext);
        let dec2 = decrypt_stream_chunk(&stream_key, &chunk2_blob).unwrap();
        assert_eq!(dec2, chunk2_plaintext);
    }

    #[test]
    fn test_decrypt_stream_chunk_rejects_too_short() {
        let stream_key = random_bytes(32);
        let short = vec![0u8; 20]; // < 12 + 16
        assert!(decrypt_stream_chunk(&stream_key, &short).is_err());
    }
}
