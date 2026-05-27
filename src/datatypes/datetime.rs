//! BACnet `Date` and `Time` primitive datatypes.
//!
//! Both have an application-tagged form (used inside lists and sequences) and,
//! for `Date`, a context-tagged form (used by `BACnetCalendarEntry`). The
//! application form delegates to the `encoding` primitives; the context form is
//! written directly because BACnet stores the year as `year - 1900` in a single
//! octet.

use crate::encoding::{
    decode_context_primitive, decode_date, decode_time, encode_context_tag, encode_date,
    encode_time, Result as EncodingResult,
};
use crate::EncodingError;

/// BACnet Date. `year` is the full year (e.g. 2026); `255` means unspecified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Date {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub weekday: u8,
}

impl Date {
    pub fn new(year: u16, month: u8, day: u8, weekday: u8) -> Self {
        Self {
            year,
            month,
            day,
            weekday,
        }
    }

    /// Encode as an application-tagged Date (tag 10).
    pub fn encode_application(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        encode_date(buffer, self.year, self.month, self.day, self.weekday)
    }

    /// Decode an application-tagged Date.
    pub fn decode_application(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let ((year, month, day, weekday), consumed) = decode_date(data)?;
        Ok((
            Self {
                year,
                month,
                day,
                weekday,
            },
            consumed,
        ))
    }

    /// Encode as a context-tagged Date: `[tag] len=4` then `year-1900, month, day, weekday`.
    pub fn encode_context(&self, buffer: &mut Vec<u8>, tag_number: u8) -> EncodingResult<()> {
        encode_context_tag(buffer, tag_number, 4)?;
        buffer.push(year_to_octet(self.year)?);
        buffer.push(self.month);
        buffer.push(self.day);
        buffer.push(self.weekday);
        Ok(())
    }

    /// Decode a context-tagged Date with the given tag number.
    pub fn decode_context(data: &[u8], tag_number: u8) -> EncodingResult<(Self, usize)> {
        let (tag, value, consumed) = decode_context_primitive(data)?;
        if tag != tag_number || value.len() != 4 {
            return Err(EncodingError::InvalidTag);
        }
        let year = if value[0] == 255 {
            255
        } else {
            1900 + u16::from(value[0])
        };
        Ok((
            Self {
                year,
                month: value[1],
                day: value[2],
                weekday: value[3],
            },
            consumed,
        ))
    }
}

/// BACnet Time. `hundredths` is hundredths of a second (0..=99).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time {
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub hundredths: u8,
}

impl Time {
    pub fn new(hour: u8, minute: u8, second: u8, hundredths: u8) -> Self {
        Self {
            hour,
            minute,
            second,
            hundredths,
        }
    }

    /// Encode as an application-tagged Time (tag 11).
    pub fn encode_application(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        encode_time(buffer, self.hour, self.minute, self.second, self.hundredths)
    }

    /// Decode an application-tagged Time.
    pub fn decode_application(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let ((hour, minute, second, hundredths), consumed) = decode_time(data)?;
        Ok((
            Self {
                hour,
                minute,
                second,
                hundredths,
            },
            consumed,
        ))
    }
}

fn year_to_octet(year: u16) -> EncodingResult<u8> {
    if year == 255 {
        return Ok(255);
    }
    year.checked_sub(1900)
        .and_then(|y| u8::try_from(y).ok())
        .ok_or_else(|| {
            EncodingError::InvalidFormat(format!("date year {year} is outside 1900..=2155"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_date_round_trips() {
        let date = Date::new(2026, 5, 4, 1);
        let mut buf = Vec::new();
        date.encode_application(&mut buf).unwrap();
        assert_eq!(buf, vec![0xA4, 0x7E, 0x05, 0x04, 0x01]);
        let (decoded, consumed) = Date::decode_application(&buf).unwrap();
        assert_eq!(decoded, date);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn context_date_round_trips() {
        let date = Date::new(2026, 12, 24, 4);
        let mut buf = Vec::new();
        date.encode_context(&mut buf, 0).unwrap();
        assert_eq!(buf, vec![0x0C, 0x7E, 0x0C, 0x18, 0x04]);
        let (decoded, consumed) = Date::decode_context(&buf, 0).unwrap();
        assert_eq!(decoded, date);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn application_time_round_trips() {
        let time = Time::new(23, 59, 59, 99);
        let mut buf = Vec::new();
        time.encode_application(&mut buf).unwrap();
        assert_eq!(buf, vec![0xB4, 0x17, 0x3B, 0x3B, 0x63]);
        let (decoded, consumed) = Time::decode_application(&buf).unwrap();
        assert_eq!(decoded, time);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn year_outside_range_is_rejected() {
        let mut buf = Vec::new();
        assert!(Date::new(1899, 1, 1, 1).encode_context(&mut buf, 0).is_err());
    }
}
