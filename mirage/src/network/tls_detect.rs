use bytes::Buf;
use std::io::Cursor;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsParseError {
    #[error("Incomplete data")]
    Incomplete,
    #[error("Invalid TLS record")]
    InvalidRecord,
    #[error("Not a ClientHello")]
    NotClientHello,
    #[error("Protocol error")]
    ProtocolError,
}

#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    pub sni: Option<String>,
    pub session_id: Option<Vec<u8>>,
    pub alpn: Option<Vec<String>>,
}

/// Parses the beginning of a TCP stream to extract ClientHello information.
/// returns `Ok(Some(info))` if successful, `Ok(None)` if incomplete, or `Err` if invalid.
pub fn parse_client_hello(buf: &[u8]) -> std::result::Result<Option<ClientHelloInfo>, TlsParseError> {
    let mut cursor = Cursor::new(buf);

    // 1. TLS Record Header (5 bytes)
    if cursor.remaining() < 5 {
        return Ok(None);
    }
    
    let content_type = cursor.get_u8();
    let _version = cursor.get_u16();
    let length = cursor.get_u16() as usize;

    // ContentType::Handshake is 22
    if content_type != 22 {
        return Err(TlsParseError::InvalidRecord);
    }

    if cursor.remaining() < length {
        return Ok(None); // Need more data
    }

    // Limit scope to the record body
    let mut reader = Cursor::new(&buf[5..5 + length]);

    // 2. Handshake Header (4 bytes)
    if reader.remaining() < 4 {
        return Err(TlsParseError::ProtocolError);
    }

    let handshake_type = reader.get_u8();
    let _handshake_len = read_u24(&mut reader);

    // HandshakeType::ClientHello is 1
    if handshake_type != 1 {
        return Err(TlsParseError::NotClientHello);
    }

    // 3. ClientHello Body
    if reader.remaining() < 2 {
        return Err(TlsParseError::ProtocolError);
    }
    let _protocol_version = reader.get_u16();

    // Random (32 bytes)
    if reader.remaining() < 32 {
        return Err(TlsParseError::ProtocolError);
    }
    reader.advance(32);

    // Session ID (1 byte length + 0..32 bytes header)
    if reader.remaining() < 1 {
        return Err(TlsParseError::ProtocolError);
    }
    let session_id_len = reader.get_u8() as usize;
    if reader.remaining() < session_id_len {
        return Err(TlsParseError::ProtocolError);
    }
    
    // Extract Session ID
    let mut session_id = None;
    if session_id_len > 0 {
        let mut id_bytes = vec![0u8; session_id_len];
        reader.copy_to_slice(&mut id_bytes);
        session_id = Some(id_bytes);
    }

    // Cipher Suites (2 bytes len + bytes)
    if reader.remaining() < 2 {
        return Err(TlsParseError::ProtocolError);
    }
    let cipher_suites_len = reader.get_u16() as usize;
    if reader.remaining() < cipher_suites_len {
        return Err(TlsParseError::ProtocolError);
    }
    reader.advance(cipher_suites_len);

    // Compression Methods (1 byte len + bytes)
    if reader.remaining() < 1 {
        return Err(TlsParseError::ProtocolError);
    }
    let compression_methods_len = reader.get_u8() as usize;
    if reader.remaining() < compression_methods_len {
        return Err(TlsParseError::ProtocolError);
    }
    reader.advance(compression_methods_len);

    // Extensions (2 bytes len + bytes)
    if reader.remaining() < 2 {
        // Extensions are optional in TLS 1.0 but mandatory in 1.2+ practically.
        // If no extensions, we are done.
        return Ok(Some(ClientHelloInfo { sni: None, session_id, alpn: None }));
    }

    let extensions_len = reader.get_u16() as usize;
    if reader.remaining() < extensions_len {
        return Err(TlsParseError::ProtocolError);
    }

    let mut ext_reader = Cursor::new(&reader.get_ref()[reader.position() as usize..reader.position() as usize + extensions_len]);
    
    let mut sni = None;
    let mut alpn = None;

    while ext_reader.remaining() >= 4 {
        let ext_type = ext_reader.get_u16();
        let ext_len = ext_reader.get_u16() as usize;

        if ext_reader.remaining() < ext_len {
            break; 
        }

        match ext_type {
            // Extension: Server Name (0x0000)
            0x0000 => {
                 if ext_len < 2 { ext_reader.advance(ext_len); continue; }
                 // SNI List Length
                 let _list_len = ext_reader.get_u16();
                 // Name Type (1 byte) + Name Len (2 bytes)
                 if ext_reader.remaining() < 3 { ext_reader.advance(ext_len - 2); continue; } // -2 because we read list_len
                 let name_type = ext_reader.get_u8();
                 let name_len = ext_reader.get_u16() as usize;
                 
                 // name_type 0 is host_name
                 if name_type == 0 && ext_reader.remaining() >= name_len {
                     let mut name_bytes = vec![0u8; name_len];
                     ext_reader.copy_to_slice(&mut name_bytes);
                     sni = String::from_utf8(name_bytes).ok();
                 }
                 // Advance remaining if any (unlikely for SNI but technically list)
                 // Just continue loop actually, we consumed what we assumed.
                 // Better to skip the rest of this extension body correctly:
                 // The ext_reader is at start_of_ext + 4 + ...
                 // We should just use a slice reader for specific extensions to be safe.
            }
            // Extension: ALPN (0x0010 = 16)
            0x0010 => {
                if ext_len < 2 { ext_reader.advance(ext_len); continue; }
                let list_len = ext_reader.get_u16() as usize;
                if ext_reader.remaining() < list_len { ext_reader.advance(ext_reader.remaining()); continue; }

                let mut alpn_reader = Cursor::new(&ext_reader.get_ref()[ext_reader.position() as usize..ext_reader.position() as usize + list_len]);
                let mut protocols = Vec::new();

                while alpn_reader.has_remaining() {
                    if alpn_reader.remaining() < 1 { break; }
                    let proto_len = alpn_reader.get_u8() as usize;
                    if alpn_reader.remaining() < proto_len { break; }
                    let mut proto_bytes = vec![0u8; proto_len];
                    alpn_reader.copy_to_slice(&mut proto_bytes);
                    if let Ok(proto_str) = String::from_utf8(proto_bytes) {
                       protocols.push(proto_str);
                    }
                }
                alpn = Some(protocols);
                
                // Advance main reader past this extension
                ext_reader.advance(list_len); 
                // We manually advanced list_len, so we don't need to advance ext_len again?
                // Wait, ext_len includes the list_len bytes (2 bytes)?
                // RFC 7301:
                // Extension data:
                // opaque protocol_name_list<2..2^16-1>;
                // So ext_len == list_len + 2 bytes (for list length field).
                // I read list_len (2 bytes). So I advanced 2 bytes.
                // Then I need to advance list_len bytes.
                // So total advanced = list_len + 2 = ext_len. Correct.
                continue; // We already advanced.
            }
            _ => {
                 ext_reader.advance(ext_len);
            }
        }
    }

    Ok(Some(ClientHelloInfo { sni, session_id, alpn }))
}

fn read_u24(cursor: &mut Cursor<&[u8]>) -> u32 {
    let b1 = cursor.get_u8() as u32;
    let b2 = cursor.get_u8() as u32;
    let b3 = cursor.get_u8() as u32;
    (b1 << 16) | (b2 << 8) | b3
}
