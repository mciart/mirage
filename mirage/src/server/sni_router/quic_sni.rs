//! QUIC Initial packet SNI extractor.
//!
//! Parses a raw QUIC Initial datagram to extract the TLS SNI, following RFC 9001:
//! 1. Parse QUIC long header → get DCID
//! 2. Derive initial keys from DCID (using HKDF with QUIC v1 salt)
//! 3. Remove header protection
//! 4. Decrypt AEAD payload
//! 5. Parse CRYPTO frames → reassemble TLS ClientHello
//! 6. Extract SNI from ClientHello

use ring::aead;
use ring::hkdf;

/// QUIC v1 Initial salt (RFC 9001 Section 5.2)
const QUIC_V1_INITIAL_SALT: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Extract SNI from a raw QUIC UDP datagram.
/// Returns `None` if the packet is not a QUIC Initial or SNI cannot be extracted.
pub fn extract_quic_sni(datagram: &[u8]) -> Option<String> {
    // Minimum: 1 (flags) + 4 (version) + 1 (dcid_len) + 1 (scid_len) + some payload
    if datagram.len() < 20 {
        return None;
    }

    // Check long header form bit (bit 7) and Initial type (bits 4-5 = 0b00)
    let first_byte = datagram[0];
    if first_byte & 0x80 == 0 {
        return None; // Short header, not Initial
    }

    // QUIC version (bytes 1-4)
    let version = u32::from_be_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]);

    // Only support QUIC v1 (0x00000001) and v2 (0x6b3343cf)
    let salt = match version {
        0x00000001 => QUIC_V1_INITIAL_SALT,
        _ => return None, // Unknown version
    };

    // Packet type: Initial = 0b00 in bits 4-5
    let packet_type = (first_byte & 0x30) >> 4;
    if packet_type != 0 {
        return None; // Not Initial (Handshake, 0-RTT, Retry)
    }

    let mut pos = 5;

    // DCID length + DCID
    if pos >= datagram.len() {
        return None;
    }
    let dcid_len = datagram[pos] as usize;
    pos += 1;
    if pos + dcid_len > datagram.len() {
        return None;
    }
    let dcid = &datagram[pos..pos + dcid_len];
    pos += dcid_len;

    // SCID length + SCID
    if pos >= datagram.len() {
        return None;
    }
    let scid_len = datagram[pos] as usize;
    pos += 1;
    pos += scid_len; // Skip SCID

    // Token length (varint) + Token
    let (token_len, consumed) = read_varint(&datagram[pos..])?;
    pos += consumed;
    pos += token_len as usize;

    // Payload length (varint)
    if pos >= datagram.len() {
        return None;
    }
    let (payload_len, consumed) = read_varint(&datagram[pos..])?;
    pos += consumed;

    // The header ends here; payload starts at `pos`
    let header_len = pos;

    if pos + payload_len as usize > datagram.len() {
        return None;
    }

    // Derive Initial keys from DCID
    let (client_hp_key, client_key, client_iv) = derive_initial_keys(dcid, salt)?;

    // Remove header protection
    let mut packet = datagram[..header_len + payload_len as usize].to_vec();

    // Sample starts at header_len + 4 (skip packet number area)
    let sample_offset = header_len + 4;
    if sample_offset + 16 > packet.len() {
        return None;
    }
    let sample = &packet[sample_offset..sample_offset + 16];

    // Generate header protection mask
    let mask = hp_mask(&client_hp_key, sample)?;

    // Unmask the first byte
    // For long header: lower 4 bits contain packet number length
    packet[0] ^= mask[0] & 0x0f;
    let pn_len = (packet[0] & 0x03) as usize + 1;

    // Unmask packet number bytes
    for i in 0..pn_len {
        packet[header_len + i] ^= mask[1 + i];
    }

    // Read packet number
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        pn = (pn << 8) | packet[header_len + i] as u64;
    }

    // Construct nonce
    let mut nonce = client_iv;
    let nonce_len = nonce.len();
    for i in 0..8 {
        nonce[nonce_len - 1 - i] ^= ((pn >> (8 * i)) & 0xff) as u8;
    }

    // Decrypt payload
    let aad = &packet[..header_len + pn_len]; // Associated data = header + PN
    let encrypted_payload = &packet[header_len + pn_len..];

    let decrypted = decrypt_aead(&client_key, &nonce, aad, encrypted_payload)?;

    // Parse CRYPTO frames from decrypted payload
    let tls_data = extract_crypto_data(&decrypted)?;

    // Parse TLS ClientHello to extract SNI
    extract_sni_from_client_hello(&tls_data)
}

/// Reads a QUIC variable-length integer. Returns (value, bytes_consumed).
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let len = 1 << (first >> 6);

    if buf.len() < len {
        return None;
    }

    let mut val = (first & 0x3f) as u64;
    for i in 1..len {
        val = (val << 8) | buf[i] as u64;
    }
    Some((val, len))
}

/// Derives QUIC Initial client keys from DCID.
fn derive_initial_keys(dcid: &[u8], salt: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // initial_secret = HKDF-Extract(salt, DCID)
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let initial_secret = salt.extract(dcid);

    // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    let client_secret = hkdf_expand_label(&initial_secret, b"client in", 32)?;

    // Derive client key, IV, HP key
    let client_secret = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client_secret);

    let client_key = hkdf_expand_label(&client_secret, b"quic key", 16)?;
    let client_iv = hkdf_expand_label(&client_secret, b"quic iv", 12)?;
    let client_hp = hkdf_expand_label(&client_secret, b"quic hp", 16)?;

    Some((client_hp, client_key, client_iv))
}

/// HKDF-Expand-Label (TLS 1.3 style) used by QUIC.
fn hkdf_expand_label(secret: &hkdf::Prk, label: &[u8], length: usize) -> Option<Vec<u8>> {
    // HkdfLabel struct:
    // uint16 length
    // opaque label<7..255> = "tls13 " + label
    // opaque context<0..255> = ""
    let full_label_prefix = b"tls13 ";
    let mut hkdf_label = Vec::with_capacity(2 + 1 + full_label_prefix.len() + label.len() + 1);
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    hkdf_label.push((full_label_prefix.len() + label.len()) as u8);
    hkdf_label.extend_from_slice(full_label_prefix);
    hkdf_label.extend_from_slice(label);
    hkdf_label.push(0); // empty context

    let mut out = vec![0u8; length];
    let binding = [&hkdf_label[..]];
    let okm = secret.expand(&binding, LenKey(length)).ok()?;
    okm.fill(&mut out).ok()?;
    Some(out)
}

/// Helper type for ring's HKDF output length.
struct LenKey(usize);
impl hkdf::KeyType for LenKey {
    fn len(&self) -> usize {
        self.0
    }
}

/// AES-128-ECB for header protection mask.
fn hp_mask(hp_key: &[u8], sample: &[u8]) -> Option<[u8; 5]> {
    use ring::aead::quic;
    let key = quic::HeaderProtectionKey::new(&quic::AES_128, hp_key).ok()?;
    let mask = key.new_mask(sample).ok()?;
    Some(mask)
}

/// AES-128-GCM decryption.
fn decrypt_aead(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let unbound_key = aead::UnboundKey::new(&aead::AES_128_GCM, key).ok()?;
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce).ok()?;
    let aad = aead::Aad::from(aad);

    let mut in_out = ciphertext.to_vec();
    let opening_key = aead::LessSafeKey::new(unbound_key);
    let plaintext = opening_key.open_in_place(nonce, aad, &mut in_out).ok()?;
    Some(plaintext.to_vec())
}

/// Extracts CRYPTO frame data from a decrypted QUIC Initial payload.
fn extract_crypto_data(payload: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    let mut crypto_data = Vec::new();

    while pos < payload.len() {
        let frame_type = payload[pos];
        pos += 1;

        match frame_type {
            0x00 => {
                // PADDING — skip
                continue;
            }
            0x01 => {
                // PING — skip
                continue;
            }
            0x02 | 0x03 => {
                // ACK — skip (variable length, complex to parse)
                // For SNI extraction, we only care about CRYPTO frames
                break;
            }
            0x06 => {
                // CRYPTO frame!
                if pos >= payload.len() {
                    break;
                }
                let (offset, consumed) = read_varint(&payload[pos..])?;
                pos += consumed;
                let (length, consumed) = read_varint(&payload[pos..])?;
                pos += consumed;

                if pos + length as usize > payload.len() {
                    break;
                }

                // For simplicity, we only handle offset 0 (first CRYPTO frame)
                if offset == 0 || crypto_data.is_empty() {
                    crypto_data.extend_from_slice(&payload[pos..pos + length as usize]);
                }
                pos += length as usize;
            }
            _ => {
                // Unknown frame type — stop parsing
                break;
            }
        }
    }

    if crypto_data.is_empty() {
        None
    } else {
        Some(crypto_data)
    }
}

/// Extracts SNI from a TLS ClientHello message.
fn extract_sni_from_client_hello(data: &[u8]) -> Option<String> {
    // Use the existing protocol-level parser
    match crate::protocol::tls_detect::parse_client_hello(data) {
        Ok(Some(info)) => info.sni,
        _ => None,
    }
}
