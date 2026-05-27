//! Schedule datatypes: `BACnetTimeValue`, weekly schedules (`Weekly_Schedule`,
//! 123) and exception schedules (`Exception_Schedule`, 38).

use crate::datatypes::calendar::CalendarEntry;
use crate::datatypes::datetime::Time;
use crate::encoding::{
    decode_context_object_id, decode_context_unsigned, decode_tag_header, encode_closing_tag,
    encode_context_object_id, encode_context_unsigned, encode_opening_tag, extract_context_block,
    Result as EncodingResult,
};
use crate::object::ObjectIdentifier;
use crate::property::{decode_property_value, encode_property_value, PropertyValue};
use crate::EncodingError;

const CALENDAR_OBJECT_TYPE: u32 = 6;

/// `BACnetTimeValue`: an application Time followed by a primitive value.
#[derive(Debug, Clone, PartialEq)]
pub struct TimeValue {
    pub time: Time,
    pub value: PropertyValue,
}

impl TimeValue {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        self.time.encode_application(buffer)?;
        encode_property_value(&self.value, buffer)
    }

    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let (time, used) = Time::decode_application(data)?;
        let (value, value_used) = decode_property_value(&data[used..])?;
        Ok((Self { time, value }, used + value_used))
    }
}

fn encode_time_values(buffer: &mut Vec<u8>, values: &[TimeValue]) -> EncodingResult<()> {
    for value in values {
        value.encode(buffer)?;
    }
    Ok(())
}

fn decode_time_values(data: &[u8]) -> EncodingResult<Vec<TimeValue>> {
    let mut values = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let (value, consumed) = TimeValue::decode(&data[pos..])?;
        if consumed == 0 {
            return Err(EncodingError::InvalidFormat(
                "time value made no progress".to_string(),
            ));
        }
        values.push(value);
        pos += consumed;
    }
    Ok(values)
}

/// `BACnetDailySchedule`: the day's list of time/value pairs (wrapped in `[0]`
/// when it appears inside a `Weekly_Schedule`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DailySchedule {
    pub time_values: Vec<TimeValue>,
}

/// `Weekly_Schedule` (123): `ARRAY[7] OF BACnetDailySchedule`.
#[derive(Debug, Clone, PartialEq)]
pub struct WeeklySchedule {
    pub days: Vec<DailySchedule>,
}

impl WeeklySchedule {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        if self.days.len() != 7 {
            return Err(EncodingError::InvalidFormat(
                "weekly schedule must contain exactly 7 daily schedules".to_string(),
            ));
        }
        for day in &self.days {
            encode_opening_tag(buffer, 0)?;
            encode_time_values(buffer, &day.time_values)?;
            encode_closing_tag(buffer, 0)?;
        }
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut days = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let header = decode_tag_header(&data[pos..])?;
            if !header.is_opening() || header.tag_number != 0 {
                break;
            }
            let (inner, consumed) = extract_context_block(&data[pos..], 0)?;
            days.push(DailySchedule {
                time_values: decode_time_values(inner)?,
            });
            pos += consumed;
        }
        Ok(Self { days })
    }
}

/// `BACnetSpecialEvent.period` CHOICE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecialEventPeriod {
    /// `calendarEntry [0]` — an inline calendar entry.
    CalendarEntry(CalendarEntry),
    /// `calendarReference [1]` — instance of a Calendar object.
    CalendarReference { calendar_instance: u32 },
}

/// `BACnetSpecialEvent`.
#[derive(Debug, Clone, PartialEq)]
pub struct SpecialEvent {
    pub period: SpecialEventPeriod,
    pub values: Vec<TimeValue>,
    pub priority: u32,
}

impl SpecialEvent {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        match &self.period {
            SpecialEventPeriod::CalendarEntry(entry) => {
                encode_opening_tag(buffer, 0)?;
                entry.encode(buffer)?;
                encode_closing_tag(buffer, 0)?;
            }
            SpecialEventPeriod::CalendarReference { calendar_instance } => {
                encode_opening_tag(buffer, 1)?;
                let object_id =
                    ObjectIdentifier::new(CALENDAR_OBJECT_TYPE.into(), *calendar_instance);
                buffer.extend_from_slice(&encode_context_object_id(object_id, 0)?);
                encode_closing_tag(buffer, 1)?;
            }
        }
        encode_opening_tag(buffer, 2)?;
        encode_time_values(buffer, &self.values)?;
        encode_closing_tag(buffer, 2)?;
        buffer.extend_from_slice(&encode_context_unsigned(self.priority, 3)?);
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let header = decode_tag_header(data)?;
        if !header.is_opening() {
            return Err(EncodingError::InvalidTag);
        }
        let mut pos = 0;
        let period = match header.tag_number {
            0 => {
                let (inner, consumed) = extract_context_block(&data[pos..], 0)?;
                pos += consumed;
                let (entry, _) = CalendarEntry::decode(inner)?;
                SpecialEventPeriod::CalendarEntry(entry)
            }
            1 => {
                let (inner, consumed) = extract_context_block(&data[pos..], 1)?;
                pos += consumed;
                let (object_id, _) = decode_context_object_id(inner, 0)?;
                SpecialEventPeriod::CalendarReference {
                    calendar_instance: object_id.instance,
                }
            }
            _ => return Err(EncodingError::InvalidTag),
        };

        let (inner, consumed) = extract_context_block(&data[pos..], 2)?;
        let values = decode_time_values(inner)?;
        pos += consumed;

        let (priority, consumed) = decode_context_unsigned(&data[pos..], 3)?;
        pos += consumed;

        Ok((
            Self {
                period,
                values,
                priority,
            },
            pos,
        ))
    }
}

/// `Exception_Schedule` (38): `LIST OF BACnetSpecialEvent`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ExceptionSchedule {
    pub events: Vec<SpecialEvent>,
}

impl ExceptionSchedule {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        for event in &self.events {
            event.encode(buffer)?;
        }
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut events = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let (event, consumed) = SpecialEvent::decode(&data[pos..])?;
            if consumed == 0 {
                return Err(EncodingError::InvalidFormat(
                    "special event made no progress".to_string(),
                ));
            }
            events.push(event);
            pos += consumed;
        }
        Ok(Self { events })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datatypes::datetime::Date;

    fn tv(hour: u8, minute: u8, value: PropertyValue) -> TimeValue {
        TimeValue {
            time: Time::new(hour, minute, 0, 0),
            value,
        }
    }

    #[test]
    fn weekly_schedule_round_trips() {
        let mut days = vec![DailySchedule::default(); 7];
        days[0].time_values = vec![
            tv(8, 0, PropertyValue::Real(21.5)),
            tv(18, 0, PropertyValue::Real(18.0)),
        ];
        let schedule = WeeklySchedule { days };

        let mut buf = Vec::new();
        schedule.encode(&mut buf).unwrap();
        assert_eq!(
            buf,
            vec![
                0x0E, 0xB4, 0x08, 0x00, 0x00, 0x00, 0x44, 0x41, 0xAC, 0x00, 0x00, 0xB4, 0x12, 0x00,
                0x00, 0x00, 0x44, 0x41, 0x90, 0x00, 0x00, 0x0F, 0x0E, 0x0F, 0x0E, 0x0F, 0x0E, 0x0F,
                0x0E, 0x0F, 0x0E, 0x0F, 0x0E, 0x0F,
            ]
        );
        assert_eq!(WeeklySchedule::decode(&buf).unwrap(), schedule);
    }

    #[test]
    fn exception_schedule_calendar_entry_round_trips() {
        let schedule = ExceptionSchedule {
            events: vec![SpecialEvent {
                period: SpecialEventPeriod::CalendarEntry(CalendarEntry::Date(Date::new(
                    2026, 12, 24, 4,
                ))),
                values: vec![tv(9, 30, PropertyValue::Enumerated(1))],
                priority: 8,
            }],
        };

        let mut buf = Vec::new();
        schedule.encode(&mut buf).unwrap();
        assert_eq!(
            buf,
            vec![
                0x0E, 0x0C, 0x7E, 0x0C, 0x18, 0x04, 0x0F, 0x2E, 0xB4, 0x09, 0x1E, 0x00, 0x00, 0x91,
                0x01, 0x2F, 0x39, 0x08,
            ]
        );
        assert_eq!(ExceptionSchedule::decode(&buf).unwrap(), schedule);
    }

    #[test]
    fn exception_schedule_calendar_reference_round_trips() {
        let schedule = ExceptionSchedule {
            events: vec![SpecialEvent {
                period: SpecialEventPeriod::CalendarReference {
                    calendar_instance: 3,
                },
                values: vec![tv(0, 0, PropertyValue::Real(1.0))],
                priority: 16,
            }],
        };
        let mut buf = Vec::new();
        schedule.encode(&mut buf).unwrap();
        assert_eq!(ExceptionSchedule::decode(&buf).unwrap(), schedule);
    }

    #[test]
    fn weekly_schedule_requires_seven_days() {
        let schedule = WeeklySchedule {
            days: vec![DailySchedule::default()],
        };
        assert!(schedule.encode(&mut Vec::new()).is_err());
    }
}
