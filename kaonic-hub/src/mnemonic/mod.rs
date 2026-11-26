//! Seed phrases for the Kaonic Admin: 12 or 24 words of the BIP39 English list, which
//! encode 128 or 256 bits from the kernel's random source and a SHA-256 checksum, so a
//! mistyped or swapped word is caught before it derives the wrong admin.

use std::io;
use std::sync::LazyLock;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::random;

/// The BIP39 English list (SHA-256 2f5eed53…dbda).
static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| include_str!("english.txt").lines().collect());

pub fn wordlist() -> &'static [&'static str] {
    &WORDS
}

#[derive(Debug, PartialEq, Eq)]
pub enum PhraseError {
    /// Not 12 or 24 words.
    Length(usize),
    /// Positions (1-based) of words not on the list.
    Unknown(Vec<usize>),
    /// Every word is on the list but the checksum fails: one is wrong or out of order.
    Checksum,
    /// A published example (every entropy byte the same, as BIP39's test vectors): anyone can
    /// derive its keys.
    Example,
}

/// A new phrase of `words` (12 or 24) words.
pub fn generate(words: usize) -> io::Result<Zeroizing<String>> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    let len = match words {
        12 => 16,
        24 => 32,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "12 or 24 words")),
    };
    random::fill(&mut entropy[..len])?;
    Ok(encode(&entropy[..len]))
}

fn encode(entropy: &[u8]) -> Zeroizing<String> {
    let checksum = Sha256::digest(entropy);
    let words = (entropy.len() * 8 + entropy.len() / 4) / 11;
    let bit = |i: usize| {
        let byte = if i < entropy.len() * 8 { entropy[i / 8] } else { checksum[(i - entropy.len() * 8) / 8] };
        u16::from(byte >> (7 - i % 8) & 1)
    };
    let mut out = Zeroizing::new(String::with_capacity(words * 9));
    for word in 0..words {
        let index = (0..11).fold(0u16, |index, i| index << 1 | bit(word * 11 + i));
        if word > 0 {
            out.push(' ');
        }
        out.push_str(WORDS[usize::from(index)]);
    }
    out
}

/// Checks a typed phrase and returns it as derived from: lowercase words, single spaces.
pub fn parse(text: &str) -> Result<Zeroizing<String>, PhraseError> {
    let typed: Zeroizing<Vec<String>> = Zeroizing::new(text.split_whitespace().map(str::to_lowercase).collect());
    if typed.len() != 12 && typed.len() != 24 {
        return Err(PhraseError::Length(typed.len()));
    }
    let indexes: Vec<Option<usize>> = typed.iter().map(|word| WORDS.binary_search(&word.as_str()).ok()).collect();
    let unknown: Vec<usize> = indexes.iter().enumerate().filter(|(_, index)| index.is_none()).map(|(at, _)| at + 1).collect();
    if !unknown.is_empty() {
        return Err(PhraseError::Unknown(unknown));
    }
    let len = typed.len() * 4 / 3;
    let mut entropy = Zeroizing::new([0u8; 32]);
    for (word, index) in indexes.iter().flatten().enumerate() {
        for i in 0..11 {
            let at = word * 11 + i;
            if at < len * 8 && index >> (10 - i) & 1 == 1 {
                entropy[at / 8] |= 0x80 >> (at % 8);
            }
        }
    }
    let phrase = encode(&entropy[..len]);
    if !phrase.split(' ').eq(typed.iter().map(String::as_str)) {
        return Err(PhraseError::Checksum);
    }
    if entropy[..len].iter().all(|byte| *byte == entropy[0]) {
        return Err(PhraseError::Example);
    }
    Ok(phrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn the_list_is_the_bip39_english_one() {
        assert_eq!(WORDS.len(), 2048);
        assert!(WORDS.windows(2).all(|pair| pair[0] < pair[1]), "sorted, for the search");
        assert_eq!((WORDS[0], WORDS[2047]), ("abandon", "zoo"));
    }

    #[test]
    fn bip39_test_vectors() {
        let vectors = [
            ("00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
            ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow"),
            ("ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            ),
        ];
        for (entropy, phrase) in vectors {
            assert_eq!(*encode(&hex(entropy)), phrase);
            // They check out, but are published: nobody's admin.
            assert_eq!(parse(phrase), Err(PhraseError::Example));
        }
    }

    #[test]
    fn typed_phrases_are_normalised_and_mistakes_are_caught() {
        let phrase = "abandon amount liar amount expire adjust cage candy arch gather drum buyer";
        assert_eq!(*encode(&(0u8..16).collect::<Vec<_>>()), phrase);
        assert_eq!(*parse("  Abandon AMOUNT liar amount\nexpire adjust cage candy arch gather drum buyer ").unwrap(), phrase);
        assert_eq!(parse("abandon amount liar"), Err(PhraseError::Length(3)));
        assert_eq!(parse(&phrase.replace("cage", "cag")), Err(PhraseError::Unknown(vec![7])));
        // Two words swapped, and one replaced by another word on the list.
        assert_eq!(parse(&phrase.replace("cage candy", "candy cage")), Err(PhraseError::Checksum));
        assert_eq!(parse(&phrase.replace("buyer", "zoo")), Err(PhraseError::Checksum));
    }

    #[test]
    fn generated_phrases_parse_and_differ() {
        for words in [12, 24] {
            let a = generate(words).unwrap();
            assert_eq!(a.split(' ').count(), words);
            assert_eq!(*parse(&a).unwrap(), *a);
            assert_ne!(*a, *generate(words).unwrap());
        }
        assert!(generate(18).is_err());
    }
}
