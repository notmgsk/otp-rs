use crate::{Otp, OtpResult, ToBytes};

/// HMAC-based one-time passcode
///
/// Uses a counter to generate the passcode. The counter is
/// incremented after a passcode is generated.
pub type Hotp = Otp<Counter>;

impl Hotp {
    /// Get a HOTP generator with the given `key`, initial count, and which
    /// generates passcodes of `length`.
    pub fn new(key: String, initial_count: u64, length: u32) -> Self {
        Otp {
            key,
            generator: Counter {
                count: initial_count,
            },
            digits: length,
        }
    }
}

/// The backing type which implements the [`ToBytes`] interface,
/// using a counter to generate the value bytes.
pub struct Counter {
    count: u64,
}

impl ToBytes for Counter {
    fn to_bytes(&mut self) -> OtpResult<[u8; 8]> {
        let c = self.count;
        self.count += 1;
        Ok(c.to_be_bytes().into())
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use crate::hotp::Hotp;

    // These test cases are copied from RFC 4226
    // https://datatracker.ietf.org/doc/html/rfc4226#appendix-D
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
        let mut hotp = Hotp::new(key, counter, digits);
        let actual = hotp.get().unwrap();
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
            let actual = htop.get().unwrap();
            assert_eq!(actual, case);
        }
    }
}
