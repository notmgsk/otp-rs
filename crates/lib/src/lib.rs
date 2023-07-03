use hmac::{digest::InvalidLength, Mac};

type Sha1Hmac = hmac::Hmac<sha1::Sha1>;

#[derive(Debug, thiserror::Error)]
pub enum HotpError {
    #[error("error when computing HMAC")]
    HmacError(#[from] InvalidLength),
}

pub type Result<T> = std::result::Result<T, HotpError>;

pub struct Hotp {
    counter: u64,
    key: String,
    len: u32,
}

impl Hotp {
    pub fn new(key: String, counter: u64, len: u32) -> Self {
        Self { counter, key, len }
    }

    pub fn get_value(&mut self) -> Result<u32> {
        // Step 1: Generate an HMAC-SHA-1 value
        let hs = hmac(self.key.clone(), self.counter)?;

        // Step 2: Generate a 4-byte string (Dynamic Truncation)
        let sbits = dt(&hs);

        //   Step 3: Compute an HOTP value
        let snum = u32::from_be_bytes(sbits);

        self.increment_counter();

        Ok(snum % 10_u32.pow(self.len))
    }

    fn increment_counter(&mut self) {
        self.counter += 1;
    }
}

fn hmac(key: String, counter: u64) -> Result<[u8; 20]> {
    let mut mac = Sha1Hmac::new_from_slice(key.as_bytes())?;
    mac.update(&counter.to_be_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn dt(hs: &[u8; 20]) -> [u8; 4] {
    let offset = dt_offset(hs);
    let mut substr = dt_substr(hs, offset);
    substr[0] &= 0b0111_1111;
    substr
}

fn dt_substr(hs: &[u8; 20], offset: u8) -> [u8; 4] {
    let substr = &hs[offset as usize..(offset + 4) as usize];
    substr.try_into().unwrap()
}

fn dt_offset(hs: &[u8; 20]) -> u8 {
    hs[19] & 0b1111
}

#[cfg(test)]
mod test {
    use hex::{FromHex, ToHex};
    use hmac::Mac;
    use test_case::test_case;

    use crate::{dt, dt_offset, dt_substr, hmac, Hotp};

    #[test]
    fn it_computes_correct_offset() {
        let s: [u8; 20] = hex_literal::hex!("1f8698690e02ca16618550ef7f19da8e945b555a");
        // Last byte is 0x5a, with low 4 bits 0xa
        let expected: [u8; 1] = hex_literal::hex!("0a");
        let actual = dt_offset(&s);
        assert_eq!(actual, expected[0]);
    }

    #[test]
    fn it_computes_correct_4byte_substring() {
        let s: [u8; 20] = hex_literal::hex!("1f8698690e02ca16618550ef7f19da8e945b555a");
        let expected: [u8; 4] = hex_literal::hex!("50ef7f19");
        let actual = dt_substr(&s, dt_offset(&s));
        assert_eq!(actual, expected);
    }

    #[test]
    fn it_computes_correct_dt() {
        let s: [u8; 20] = hex_literal::hex!("1f8698690e02ca166185ffef7f19da8e945b555a");
        let expected: [u8; 4] = hex_literal::hex!("7fef7f19");
        let actual = dt(&s);
        assert_eq!(actual, expected);
    }

    #[test_case(0, "cc93cf18508d94934c64b65d8ba7667fb7cde4b0")]
    #[test_case(1, "75a48a19d4cbe100644e8ac1397eea747a2d33ab")]
    #[test_case(2, "0bacb7fa082fef30782211938bc1c5e70416ff44")]
    #[test_case(3, "66c28227d03a2d5529262ff016a1e6ef76557ece")]
    #[test_case(4, "a904c900a64b35909874b33e61c5938a8e15ed1c")]
    #[test_case(5, "a37e783d7b7233c083d4f62926c7a25f238d0316")]
    #[test_case(6, "bc9cd28561042c83f219324d3c607256c03272ae")]
    #[test_case(7, "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa")]
    #[test_case(8, "1b3c89f65e6c9e883012052823443f048b4332db")]
    #[test_case(9, "1637409809a679dc698207310c8c7fc07290d9e5")]
    fn it_computes_correct_hmac(counter: u64, expected: &str) {
        let expected = <[u8; 20]>::from_hex(expected).unwrap();
        let key = "12345678901234567890".to_string();
        let hmac = hmac(key, counter).unwrap();
        assert_eq!(hmac, expected);
    }

    #[test_case(0, 755224)]
    #[test_case(1, 287082)]
    #[test_case(2, 359152)]
    #[test_case(3, 969429)]
    #[test_case(4, 338314)]
    #[test_case(5, 254676)]
    #[test_case(6, 287922)]
    #[test_case(7, 162583)]
    #[test_case(8, 399871)]
    #[test_case(9, 520489)]
    fn it_computes_correct_hotp(counter: u64, expected: u32) {
        let key = "12345678901234567890".to_string();
        let digits = 6;
        let mut htop = Hotp::new(key, counter, digits);
        let actual = htop.get_value().unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn it_increments_the_counter() {
        let cases = vec![
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        let key = "12345678901234567890".to_string();
        let digits = 6;
        let counter = 0;
        let mut htop = Hotp::new(key, counter, digits);
        for case in cases {
            let actual = htop.get_value().unwrap();
            assert_eq!(actual, case);
        }
    }
}
