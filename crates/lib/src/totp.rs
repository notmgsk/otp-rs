use crate::{Otp, OtpResult, ToBytes};

use unix_time::Instant;

/// Time-based one-time passcode.
///
/// Provides one-time passcodes that are valid within a window
/// of time after the passcode is generated.
pub type Totp = Otp<Time>;

impl Totp {
    /// Get a TOTP generator.
    ///
    /// Repeated calls to [`Self::get`] will return the same
    /// passcode when in the same `window`.
    pub fn new(key: String, t0: Instant, window: u64, length: u32) -> Self {
        Totp::new_with_now(key, t0, window, length, Box::new(|| Instant::now()))
    }

    /// Get a TOTP generator with a custom function to provide the
    /// "now" value.
    ///
    /// See [`Self::new`].
    pub fn new_with_now(
        key: String,
        t0: Instant,
        step: u64,
        digits: u32,
        now: Box<dyn Fn() -> Instant>,
    ) -> Self {
        Otp {
            key,
            generator: Time { t0, step, now },
            digits,
        }
    }
}

/// The backing type which implements the [`ToBytes`] interface,
/// using the current time to generate the value bytes.
pub struct Time {
    t0: Instant,
    step: u64,
    now: Box<dyn Fn() -> Instant>,
}

impl ToBytes for Time {
    fn to_bytes(&mut self) -> OtpResult<[u8; 8]> {
        let t0 = self.t0;
        let now = (self.now)();
        let elapsed = now - t0;
        let steps = elapsed.as_secs() / self.step;
        Ok(steps.to_be_bytes().into())
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;
    use unix_time::Instant;

    use crate::Totp;

    // These test cases are copied from RFC 6238
    // https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
    #[test_case(59, 94287082)]
    #[test_case(1111111109, 07081804)]
    #[test_case(1111111111, 14050471)]
    #[test_case(1234567890, 89005924)]
    #[test_case(2000000000, 69279037)]
    #[test_case(20000000000, 65353130)]
    fn it_computes_correct_totp(count: u64, expected_code: u32) {
        let digits = 8;
        let key = "12345678901234567890".to_string();
        let step = 30;
        let t0 = Instant::at(0, 0);
        let mut otp = Totp::new_with_now(
            key,
            t0,
            step,
            digits,
            Box::new(move || Instant::at(count, 0)),
        );
        let actual_code = otp.get().unwrap();
        assert_eq!(actual_code, expected_code);
    }
}
