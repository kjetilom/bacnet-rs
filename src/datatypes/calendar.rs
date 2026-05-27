//! `BACnetCalendarEntry` and the `Date_List` property datatype.

use crate::datatypes::datetime::Date;
use crate::encoding::{
    decode_context_primitive, decode_tag_header, encode_closing_tag, encode_context_tag,
    encode_opening_tag, extract_context_block, Result as EncodingResult,
};
use crate::EncodingError;

/// `BACnetWeekNDay`: month (1-14, 13=odd, 14=even, 0xFF=any), week-of-month
/// (1-6, 6=last, 0xFF=any), day-of-week (1=Mon..7=Sun, 0xFF=any).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeekNDay {
    pub month: u8,
    pub week_of_month: u8,
    pub day_of_week: u8,
}

/// `BACnetCalendarEntry` CHOICE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarEntry {
    /// `date [0]` — a single date (context-tagged).
    Date(Date),
    /// `dateRange [1]` — inclusive range of two application dates.
    DateRange { start: Date, end: Date },
    /// `weekNDay [2]` — recurring week-and-day pattern.
    WeekNDay(WeekNDay),
}

impl CalendarEntry {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        match self {
            CalendarEntry::Date(date) => date.encode_context(buffer, 0),
            CalendarEntry::DateRange { start, end } => {
                encode_opening_tag(buffer, 1)?;
                start.encode_application(buffer)?;
                end.encode_application(buffer)?;
                encode_closing_tag(buffer, 1)
            }
            CalendarEntry::WeekNDay(week) => {
                encode_context_tag(buffer, 2, 3)?;
                buffer.extend_from_slice(&[week.month, week.week_of_month, week.day_of_week]);
                Ok(())
            }
        }
    }

    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let header = decode_tag_header(data)?;
        if !header.is_context() {
            return Err(EncodingError::InvalidTag);
        }
        match header.tag_number {
            0 => {
                let (date, consumed) = Date::decode_context(data, 0)?;
                Ok((CalendarEntry::Date(date), consumed))
            }
            1 => {
                let (inner, consumed) = extract_context_block(data, 1)?;
                let (start, used) = Date::decode_application(inner)?;
                let (end, _) = Date::decode_application(&inner[used..])?;
                Ok((CalendarEntry::DateRange { start, end }, consumed))
            }
            2 => {
                let (_, value, consumed) = decode_context_primitive(data)?;
                if value.len() != 3 {
                    return Err(EncodingError::InvalidLength);
                }
                Ok((
                    CalendarEntry::WeekNDay(WeekNDay {
                        month: value[0],
                        week_of_month: value[1],
                        day_of_week: value[2],
                    }),
                    consumed,
                ))
            }
            _ => Err(EncodingError::InvalidTag),
        }
    }
}

/// `Date_List` property (23): a `LIST OF BACnetCalendarEntry` with no enclosing tags.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DateList {
    pub entries: Vec<CalendarEntry>,
}

impl DateList {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        for entry in &self.entries {
            entry.encode(buffer)?;
        }
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut entries = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let (entry, consumed) = CalendarEntry::decode(&data[pos..])?;
            if consumed == 0 {
                return Err(EncodingError::InvalidFormat(
                    "calendar entry made no progress".to_string(),
                ));
            }
            entries.push(entry);
            pos += consumed;
        }
        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_date_round_trips() {
        let list = DateList {
            entries: vec![CalendarEntry::Date(Date::new(2026, 5, 4, 1))],
        };
        let mut buf = Vec::new();
        list.encode(&mut buf).unwrap();
        assert_eq!(buf, vec![0x0C, 0x7E, 0x05, 0x04, 0x01]);
        assert_eq!(DateList::decode(&buf).unwrap(), list);
    }

    #[test]
    fn date_range_round_trips() {
        let entry = CalendarEntry::DateRange {
            start: Date::new(2026, 1, 1, 4),
            end: Date::new(2026, 12, 31, 4),
        };
        let mut buf = Vec::new();
        entry.encode(&mut buf).unwrap();
        let (decoded, consumed) = CalendarEntry::decode(&buf).unwrap();
        assert_eq!(decoded, entry);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn week_n_day_round_trips() {
        let entry = CalendarEntry::WeekNDay(WeekNDay {
            month: 1,
            week_of_month: 1,
            day_of_week: 7,
        });
        let mut buf = Vec::new();
        entry.encode(&mut buf).unwrap();
        assert_eq!(buf, vec![0x2B, 0x01, 0x01, 0x07]);
        let (decoded, _) = CalendarEntry::decode(&buf).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn mixed_list_round_trips() {
        let list = DateList {
            entries: vec![
                CalendarEntry::Date(Date::new(2026, 5, 4, 1)),
                CalendarEntry::WeekNDay(WeekNDay {
                    month: 13,
                    week_of_month: 6,
                    day_of_week: 1,
                }),
            ],
        };
        let mut buf = Vec::new();
        list.encode(&mut buf).unwrap();
        assert_eq!(DateList::decode(&buf).unwrap(), list);
    }
}
