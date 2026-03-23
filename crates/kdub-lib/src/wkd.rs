use sha1::{Digest, Sha1};

/// zbase32 encoding alphabet.
const ZBASE32_ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// Encode bytes using zbase32 encoding.
///
/// zbase32 is a human-oriented base-32 encoding used by the Web Key Directory
/// protocol (RFC draft) to hash local parts of email addresses.
pub fn zbase32_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let mut result = String::new();
    let bit_count = data.len() * 8;
    let mut bit_index = 0;

    while bit_index < bit_count {
        let mut value: u32 = 0;
        for i in 0..5 {
            let pos = bit_index + i;
            if pos < bit_count {
                let byte_idx = pos / 8;
                let bit_idx = 7 - (pos % 8);
                if data[byte_idx] & (1 << bit_idx) != 0 {
                    value |= 1 << (4 - i);
                }
            }
        }
        result.push(ZBASE32_ALPHABET[value as usize] as char);
        bit_index += 5;
    }

    result
}

/// Compute the WKD hash for an email address.
///
/// The WKD hash is `zbase32(sha1(lowercase(local_part)))` where `local_part` is
/// the portion of the email before the `@` sign. The local part is lowercased
/// per the WKD specification.
///
/// Returns `(hash, domain)` where `hash` is the zbase32-encoded SHA-1 of the
/// lowercased local part, and `domain` is the domain portion of the email.
///
/// Returns `None` if the email does not contain exactly one `@`.
pub fn wkd_hash(email: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return None;
    }

    let local_part = parts[0].to_lowercase();
    let domain = parts[1].to_lowercase();

    // Reject domains with path-unsafe characters to prevent directory traversal
    // when the domain is used in filesystem paths (e.g., WKD webroot structure).
    if domain
        .bytes()
        .any(|b| b == b'/' || b == b'\\' || b == b'\0')
        || domain.contains("..")
    {
        return None;
    }

    let mut hasher = Sha1::new();
    hasher.update(local_part.as_bytes());
    let digest = hasher.finalize();

    let hash = zbase32_encode(&digest);
    Some((hash, domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zbase32_encode_empty() {
        assert_eq!(zbase32_encode(b""), "");
    }

    #[test]
    fn test_zbase32_encode_known_vectors() {
        // Single zero byte: 00000000 -> 00000 | 000(pad) -> "yy"
        assert_eq!(zbase32_encode(&[0x00]), "yy");
        // Single byte 0xFF: 11111111 -> 11111 | 111(pad) -> 31='9', 28='h' -> "9h"
        assert_eq!(zbase32_encode(&[0xFF]), "9h");
        // Two zero bytes: 16 bits -> 4 quintuples (20 bits, padded)
        assert_eq!(zbase32_encode(&[0x00, 0x00]), "yyyy");
        // Verify against GnuPG known vector: SHA-1("joe.doe") -> zbase32
        // SHA-1("joe.doe") = a83ee94be89c48a11ed25ab44cfdc848833c8b6e
        let sha1_joe_doe: [u8; 20] = [
            0xa8, 0x3e, 0xe9, 0x4b, 0xe8, 0x9c, 0x48, 0xa1, 0x1e, 0xd2, 0x5a, 0xb4, 0x4c, 0xfd,
            0xc8, 0x48, 0x83, 0x3c, 0x8b, 0x6e,
        ];
        assert_eq!(
            zbase32_encode(&sha1_joe_doe),
            "iy9q119eutrkn8s1mk4r39qejnbu3n5q"
        );
    }

    #[test]
    fn test_zbase32_encode_consistency() {
        // Same input always produces same output
        let data = b"test data for encoding";
        let result1 = zbase32_encode(data);
        let result2 = zbase32_encode(data);
        assert_eq!(result1, result2);
        // Result should only contain zbase32 alphabet characters
        for c in result1.chars() {
            assert!(
                ZBASE32_ALPHABET.contains(&(c as u8)),
                "unexpected character '{c}' in zbase32 output"
            );
        }
    }

    #[test]
    fn test_wkd_hash_basic() {
        // Known test: the WKD hash for "joe@example.com" is well-documented
        // local part "joe" -> SHA-1 -> zbase32
        let result = wkd_hash("joe@example.com");
        assert!(result.is_some());
        let (hash, domain) = result.unwrap();
        assert_eq!(domain, "example.com");
        // The hash should be a non-empty zbase32 string
        assert!(!hash.is_empty());
        // Verify it's valid zbase32
        for c in hash.chars() {
            assert!(
                ZBASE32_ALPHABET.contains(&(c as u8)),
                "unexpected character '{c}' in WKD hash"
            );
        }
    }

    #[test]
    fn test_wkd_hash_case_insensitive() {
        // Uppercase and lowercase local parts should produce the same hash
        let (hash_lower, domain_lower) = wkd_hash("alice@example.com").unwrap();
        let (hash_upper, domain_upper) = wkd_hash("Alice@Example.com").unwrap();
        assert_eq!(
            hash_lower, hash_upper,
            "WKD hash should be case-insensitive"
        );
        assert_eq!(domain_lower, domain_upper, "domain should be lowercased");
    }

    #[test]
    fn test_wkd_hash_known_value() {
        // GnuPG's known test vector: "Joe.Doe@example.org"
        // SHA-1("joe.doe") = a83ee94be89c48a11ed25ab44cfdc848833c8b6e
        // zbase32 of that SHA-1 hash = "iy9q119eutrkn8s1mk4r39qejnbu3n5q"
        let (hash, domain) = wkd_hash("Joe.Doe@example.org").unwrap();
        assert_eq!(domain, "example.org");
        assert_eq!(hash, "iy9q119eutrkn8s1mk4r39qejnbu3n5q");
    }

    #[test]
    fn test_wkd_hash_no_at_sign() {
        assert!(wkd_hash("noemail").is_none());
    }

    #[test]
    fn test_wkd_hash_empty_local() {
        assert!(wkd_hash("@example.com").is_none());
    }

    #[test]
    fn test_wkd_hash_empty_domain() {
        assert!(wkd_hash("user@").is_none());
    }

    #[test]
    fn test_wkd_hash_rejects_path_traversal_domain() {
        assert!(wkd_hash("user@../../etc").is_none());
        assert!(wkd_hash("user@foo/bar").is_none());
        assert!(wkd_hash("user@foo\\bar").is_none());
        assert!(wkd_hash("user@..").is_none());
    }
}
