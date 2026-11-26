//! Which sound card PTT uses when its device is `auto`: a USB headset when one is plugged in
//! (the newest, if several), else the board's own audio. Read from `/proc/asound/cards`, so a
//! headset plugged in or out is noticed on the next look.

/// The device setting that follows the headset.
pub const AUTO: &str = "auto";

#[derive(Debug, PartialEq, Eq)]
pub struct Card {
    pub index: u32,
    /// The card's id, as ALSA names it in `CARD=`.
    pub id: String,
    pub driver: String,
    pub name: String,
}

/// The cards in the text of `/proc/asound/cards`: ` 1 [Headset        ]: USB-Audio - Logitech USB Headset`.
pub fn parse(text: &str) -> Vec<Card> {
    text.lines()
        .filter_map(|line| {
            let (index, rest) = line.trim_start().split_once(' ')?;
            let index = index.parse().ok()?;
            let rest = rest.trim_start().strip_prefix('[')?;
            let (id, rest) = rest.split_once(']')?;
            let (driver, name) = rest.trim_start().strip_prefix(':')?.split_once(" - ")?;
            Some(Card { index, id: id.trim().to_owned(), driver: driver.trim().to_owned(), name: name.trim().to_owned() })
        })
        .collect()
}

/// The ALSA device for a setting: `auto` becomes the newest USB card, else `default`; any
/// other name is used as it is.
pub fn resolve(setting: &str, cards: &[Card]) -> String {
    if setting != AUTO {
        return setting.to_owned();
    }
    cards
        .iter()
        .filter(|card| card.driver == "USB-Audio")
        .max_by_key(|card| card.index)
        // plughw converts the rate and channels a headset wants to and from the codec's.
        .map_or_else(|| "default".to_owned(), |card| format!("plughw:CARD={},DEV=0", card.id))
}

/// The cards now present; none without ALSA.
pub fn present() -> Vec<Card> {
    std::fs::read_to_string("/proc/asound/cards").map(|text| parse(&text)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOARD: &str = " 0 [STM32MP1DK     ]: STM32MP1-DK - STM32MP1-DK\n                      STM32MP1-DK\n";
    const HEADSET: &str = " 1 [Headset        ]: USB-Audio - Logitech USB Headset\n                      Logitech Logitech USB Headset at usb-49000000.usb-otg-1, full speed\n";
    const SECOND: &str = " 2 [Device         ]: USB-Audio - USB Audio Device\n                      C-Media USB Audio Device at usb-49000000.usb-otg-1.2, full speed\n";

    #[test]
    fn reads_the_cards() {
        let cards = parse(&format!("{BOARD}{HEADSET}"));
        assert_eq!(cards.len(), 2);
        assert_eq!(cards[1], Card { index: 1, id: "Headset".into(), driver: "USB-Audio".into(), name: "Logitech USB Headset".into() });
        assert!(parse("--- no soundcards ---\n").is_empty());
    }

    #[test]
    fn auto_follows_the_newest_headset_and_falls_back_to_the_board() {
        assert_eq!(resolve(AUTO, &parse(BOARD)), "default");
        assert_eq!(resolve(AUTO, &parse(&format!("{BOARD}{HEADSET}"))), "plughw:CARD=Headset,DEV=0");
        assert_eq!(resolve(AUTO, &parse(&format!("{BOARD}{HEADSET}{SECOND}"))), "plughw:CARD=Device,DEV=0");
        assert_eq!(resolve(AUTO, &[]), "default");
        assert_eq!(resolve("hw:0,0", &parse(&format!("{BOARD}{HEADSET}"))), "hw:0,0", "a chosen device stays");
    }
}
