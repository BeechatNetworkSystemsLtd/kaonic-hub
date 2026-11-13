//! Base64 (RFC 4648): the standard alphabet with padding, and the URL-safe one without.
//! Encoding is always canonical; each decoder is as strict as its callers need.

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STANDARD_VALUES: [u8; 256] = values(STANDARD);
const URL_SAFE_VALUES: [u8; 256] = values(URL_SAFE);
const NONE: u8 = 0xff;

/// Each byte's value in `alphabet`, or [`NONE`].
const fn values(alphabet: &[u8; 64]) -> [u8; 256] {
    let mut table = [NONE; 256];
    let mut index = 0;
    while index < 64 {
        table[alphabet[index] as usize] = index as u8;
        index += 1;
    }
    table
}

/// The standard alphabet, padded.
pub fn encode(bytes: &[u8]) -> String {
    encode_with(bytes, STANDARD, true)
}

/// The URL-safe alphabet, without padding.
pub fn encode_url(bytes: &[u8]) -> String {
    encode_with(bytes, URL_SAFE, false)
}

fn encode_with(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let acc = chunk.iter().enumerate().fold(0u32, |acc, (index, &byte)| acc | (byte as u32) << (16 - 8 * index));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(alphabet[(acc >> (18 - 6 * index) & 63) as usize] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// The standard alphabet with padding; the unused bits of the last group are not checked.
/// None for anything else (whitespace included).
pub fn decode(text: &str) -> Option<Vec<u8>> {
    padded(text, false)
}

/// As [`decode`], and only the canonical spelling: the unused bits of the last group must
/// be zero, so every value has one.
pub fn decode_canonical(text: &str) -> Option<Vec<u8>> {
    padded(text, true)
}

/// The standard alphabet, as in a PEM body: whitespace anywhere is skipped and the
/// padding may be left out.
pub fn decode_loose(text: &str) -> Option<Vec<u8>> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    groups(text.trim_end_matches('=').as_bytes(), &STANDARD_VALUES, false)
}

/// The URL-safe alphabet without padding; the unused bits of the last group are not checked.
pub fn decode_url(text: &str) -> Option<Vec<u8>> {
    groups(text.as_bytes(), &URL_SAFE_VALUES, false)
}

fn padded(text: &str, canonical: bool) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|&&byte| byte == b'=').count();
    if padding > 2 {
        return None;
    }
    groups(&bytes[..bytes.len() - padding], &STANDARD_VALUES, canonical)
}

/// Groups of four characters, the last of two or three; `=` is not in either alphabet.
fn groups(text: &[u8], values: &[u8; 256], canonical: bool) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 2);
    for chunk in text.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut acc = 0u32;
        for (index, &byte) in chunk.iter().enumerate() {
            let value = values[byte as usize];
            if value == NONE {
                return None;
            }
            acc |= (value as u32) << (18 - 6 * index);
        }
        let bytes = acc.to_be_bytes();
        let take = chunk.len() - 1;
        if canonical && bytes[1 + take..].iter().any(|&byte| byte != 0) {
            return None;
        }
        out.extend_from_slice(&bytes[1..1 + take]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: [(&str, &str); 7] = [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")];

    fn sample(length: usize) -> Vec<u8> {
        (0..length).map(|n| (n * 53 + 7) as u8).collect()
    }

    #[test]
    fn matches_rfc_4648() {
        for (plain, coded) in VECTORS {
            assert_eq!(encode(plain.as_bytes()), coded);
            assert_eq!(encode_url(plain.as_bytes()), coded.trim_end_matches('='));
            for decoded in [decode(coded), decode_canonical(coded), decode_loose(coded), decode_url(coded.trim_end_matches('='))] {
                assert_eq!(decoded.unwrap(), plain.as_bytes(), "{coded}");
            }
        }
        assert_eq!(encode(&[0xfb, 0xff]), "+/8=");
        assert_eq!(encode(&[0xff, 0xfe, 0x00]), "//4A");
        assert_eq!(encode_url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn round_trips() {
        for length in 0..40 {
            let bytes = sample(length);
            assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
            assert_eq!(decode_canonical(&encode(&bytes)).unwrap(), bytes);
            assert_eq!(decode_loose(&encode(&bytes)).unwrap(), bytes);
            assert_eq!(decode_url(&encode_url(&bytes)).unwrap(), bytes);
        }
    }

    #[test]
    fn padded_refuses_what_is_not_base64() {
        for bad in ["aGk", "a===", "====", "aG=k", "a!==", "aGk=aGk=", "Zm9v\n", "Zm9v YmFy", "-_8="] {
            assert!(decode(bad).is_none(), "{bad}");
            assert!(decode_canonical(bad).is_none(), "{bad}");
        }
        // Unused bits set: taken by `decode`, refused by `decode_canonical`.
        for spelling in ["aGl=", "Zh==", "Zm9=", "Zm9vYh=="] {
            assert!(decode(spelling).is_some(), "{spelling}");
            assert!(decode_canonical(spelling).is_none(), "{spelling}");
        }
        assert_eq!(decode("aGl=").unwrap(), b"hi");
    }

    #[test]
    fn loose_skips_whitespace_and_padding() {
        let bytes = sample(91);
        let coded = encode(&bytes);
        let wrapped: String = coded.as_bytes().chunks(64).map(|line| format!("{}\n", std::str::from_utf8(line).unwrap())).collect();
        assert_eq!(decode_loose(&wrapped).unwrap(), bytes);
        assert_eq!(decode_loose(" Zm9v\r\n YmE ").unwrap(), b"fooba");
        assert_eq!(decode_loose("Zg").unwrap(), b"f");
        for bad in ["a", "a===", "Zm9vY", "Zg=a", "Zm9v!", "-_8"] {
            assert!(decode_loose(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn url_safe_has_no_padding() {
        for bad in ["Zg==", "Zm8=", "+/8", "a", "Zm9vY"] {
            assert!(decode_url(bad).is_none(), "{bad}");
        }
        let token = encode_url(&sample(64));
        assert!(!token.contains(['=', '+', '/']));
    }
}
