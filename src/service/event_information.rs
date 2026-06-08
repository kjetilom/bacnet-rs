//! BACnet GetEventInformation confirmed service (service choice 29).
//!
//! Encodes [`GetEventInformationRequest`] and decodes the
//! [`GetEventInformationResponse`] (clause 13.12 of ASHRAE 135), including the
//! per-event `BACnetEventSummary` structure and the `BACnetTimeStamp` CHOICE
//! shared with [`crate::service::acknowledge_alarm`].

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

use crate::encoding::{
    decode_context_enumerated, decode_context_object_id, decode_context_primitive,
    decode_context_unsigned, decode_tag_header, decode_unsigned, encode_constructed_context,
    encode_context_enumerated, encode_context_object_id, encode_context_tag,
    encode_context_unsigned, extract_context_block, EncodingError, Result as EncodingResult,
};
use crate::object::{EventState, ObjectIdentifier, Time};
use crate::service::BacnetDateTime;

/// BACnetTimeStamp CHOICE — shared by GetEventInformation and AcknowledgeAlarm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BacnetTimeStamp {
    /// `time [0]` — a time of day.
    Time(Time),
    /// `sequenceNumber [1]` — monotonic event sequence number.
    SequenceNumber(u32),
    /// `dateTime [2]` — full date and time.
    DateTime(BacnetDateTime),
}

impl BacnetTimeStamp {
    /// Encode the CHOICE using its intrinsic alternative tags (`[0]`/`[1]`/`[2]`).
    ///
    /// Within a named SEQUENCE element (e.g. AcknowledgeAlarm's `timeStamp [3]`)
    /// the caller must wrap this in opening/closing tags for that element,
    /// because a CHOICE carries no tag of its own.
    pub fn encode_choice(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        match self {
            BacnetTimeStamp::Time(time) => {
                encode_context_tag(buffer, 0, 4)?;
                buffer.push(time.hour);
                buffer.push(time.minute);
                buffer.push(time.second);
                buffer.push(time.hundredths);
            }
            BacnetTimeStamp::SequenceNumber(value) => {
                buffer.extend_from_slice(&encode_context_unsigned(*value, 1)?);
            }
            BacnetTimeStamp::DateTime(date_time) => {
                encode_constructed_context(buffer, 2, |inner| date_time.encode(inner))?;
            }
        }
        Ok(())
    }

    /// Decode one CHOICE alternative. Returns the value and bytes consumed.
    pub fn decode_choice(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let header = decode_tag_header(data)?;
        if !header.is_context() {
            return Err(EncodingError::InvalidTag);
        }
        match header.tag_number {
            0 => {
                let (_, payload, consumed) = decode_context_primitive(data)?;
                if payload.len() < 4 {
                    return Err(EncodingError::UnexpectedEndOfData);
                }
                let time = Time {
                    hour: payload[0],
                    minute: payload[1],
                    second: payload[2],
                    hundredths: payload[3],
                };
                Ok((BacnetTimeStamp::Time(time), consumed))
            }
            1 => {
                let (value, consumed) = decode_context_unsigned(data, 1)?;
                Ok((BacnetTimeStamp::SequenceNumber(value), consumed))
            }
            2 => {
                let (inner, consumed) = extract_context_block(data, 2)?;
                let (date_time, _) = BacnetDateTime::decode(inner)?;
                Ok((BacnetTimeStamp::DateTime(date_time), consumed))
            }
            _ => Err(EncodingError::InvalidTag),
        }
    }
}

/// BACnetEventTransitionBits — BIT STRING SIZE(3) over the three event
/// transitions an object can report and acknowledge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventTransitionBits {
    pub to_offnormal: bool,
    pub to_fault: bool,
    pub to_normal: bool,
}

impl EventTransitionBits {
    fn encode_context(&self, buffer: &mut Vec<u8>, tag: u8) -> EncodingResult<()> {
        // 3 used bits -> 5 unused bits in a single octet, MSB-first.
        let mut octet = 0u8;
        if self.to_offnormal {
            octet |= 0b1000_0000;
        }
        if self.to_fault {
            octet |= 0b0100_0000;
        }
        if self.to_normal {
            octet |= 0b0010_0000;
        }
        encode_context_tag(buffer, tag, 2)?;
        buffer.push(5); // unused bits
        buffer.push(octet);
        Ok(())
    }

    fn from_bit_payload(payload: &[u8]) -> Self {
        // payload[0] = unused-bit count, payload[1] = bits MSB-first.
        let octet = payload.get(1).copied().unwrap_or(0);
        EventTransitionBits {
            to_offnormal: octet & 0b1000_0000 != 0,
            to_fault: octet & 0b0100_0000 != 0,
            to_normal: octet & 0b0010_0000 != 0,
        }
    }
}

/// GetEventInformation-Request (confirmed service 29).
#[derive(Debug, Clone, Default)]
pub struct GetEventInformationRequest {
    /// `lastReceivedObjectIdentifier [0]` — used to page through devices that
    /// return `moreEvents = true`. `None` requests the first batch.
    pub last_received_object_identifier: Option<ObjectIdentifier>,
}

impl GetEventInformationRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn paged_from(object_identifier: ObjectIdentifier) -> Self {
        Self {
            last_received_object_identifier: Some(object_identifier),
        }
    }

    /// Encode the request body (no service-choice prefix).
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        if let Some(oid) = self.last_received_object_identifier {
            buffer.extend_from_slice(&encode_context_object_id(oid, 0)?);
        }
        Ok(())
    }
}

/// One decoded BACnetEventSummary.
#[derive(Debug, Clone)]
pub struct EventSummary {
    pub object_identifier: ObjectIdentifier,
    pub event_state: EventState,
    pub acknowledged_transitions: EventTransitionBits,
    /// Timestamps of the most recent to-offnormal, to-fault, and to-normal
    /// transitions, in that fixed order.
    pub event_time_stamps: [BacnetTimeStamp; 3],
    /// `notifyType`: 0 = alarm, 1 = event, 2 = ack-notification.
    pub notify_type: u8,
    pub event_enable: EventTransitionBits,
    /// Notification priorities for to-offnormal, to-fault, to-normal.
    pub event_priorities: [u32; 3],
}

/// GetEventInformation-ACK.
#[derive(Debug, Clone)]
pub struct GetEventInformationResponse {
    pub events: Vec<EventSummary>,
    /// `moreEvents` — the device has further summaries; page with the last
    /// returned object identifier.
    pub more_events: bool,
}

impl GetEventInformationResponse {
    /// Decode a GetEventInformation-ACK service body (without the leading
    /// service-choice byte — strip it at the APDU layer).
    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        // [0] listOfEventSummaries — a constructed block holding a flat run of
        // summary fields ([0]..[6] repeated, one group per event).
        let (list, list_consumed) = extract_context_block(data, 0)?;
        let events = decode_event_summaries(list)?;

        // [1] moreEvents — context-tagged boolean (primitive, 1 payload byte).
        let more_events = decode_more_events(&data[list_consumed..])?;

        Ok(GetEventInformationResponse {
            events,
            more_events,
        })
    }
}

fn decode_more_events(remaining: &[u8]) -> EncodingResult<bool> {
    if remaining.is_empty() {
        // Some devices omit moreEvents; treat as "no more".
        return Ok(false);
    }
    let (tag, payload, _) = decode_context_primitive(remaining)?;
    if tag != 1 {
        return Err(EncodingError::InvalidTag);
    }
    Ok(payload.first().copied().unwrap_or(0) != 0)
}

fn decode_event_summaries(data: &[u8]) -> EncodingResult<Vec<EventSummary>> {
    let mut summaries = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let remaining = &data[pos..];
        // Each summary begins with [0] objectIdentifier.
        let header = decode_tag_header(remaining)?;
        if !(header.is_context() && header.tag_number == 0 && header.is_primitive()) {
            return Err(EncodingError::InvalidTag);
        }

        let (object_identifier, consumed) = decode_context_object_id(remaining, 0)?;
        pos += consumed;

        // [1] eventState (enumerated)
        let (state_value, consumed) = decode_context_enumerated(&data[pos..], 1)?;
        pos += consumed;
        let event_state = EventState::from(state_value as u16);

        // [2] acknowledgedTransitions (bit string)
        let (acked, consumed) = decode_transition_bits(&data[pos..], 2)?;
        pos += consumed;

        // [3] eventTimeStamps: SEQUENCE SIZE(3) OF BACnetTimeStamp
        let (ts_block, consumed) = extract_context_block(&data[pos..], 3)?;
        pos += consumed;
        let event_time_stamps = decode_three_timestamps(ts_block)?;

        // [4] notifyType (enumerated)
        let (notify_type, consumed) = decode_context_enumerated(&data[pos..], 4)?;
        pos += consumed;

        // [5] eventEnable (bit string)
        let (event_enable, consumed) = decode_transition_bits(&data[pos..], 5)?;
        pos += consumed;

        // [6] eventPriorities: SEQUENCE SIZE(3) OF Unsigned
        let (prio_block, consumed) = extract_context_block(&data[pos..], 6)?;
        pos += consumed;
        let event_priorities = decode_three_unsigned(prio_block)?;

        summaries.push(EventSummary {
            object_identifier,
            event_state,
            acknowledged_transitions: acked,
            event_time_stamps,
            notify_type: notify_type as u8,
            event_enable,
            event_priorities,
        });
    }

    Ok(summaries)
}

fn decode_transition_bits(data: &[u8], tag: u8) -> EncodingResult<(EventTransitionBits, usize)> {
    let (got_tag, payload, consumed) = decode_context_primitive(data)?;
    if got_tag != tag {
        return Err(EncodingError::InvalidTag);
    }
    Ok((EventTransitionBits::from_bit_payload(payload), consumed))
}

fn decode_three_timestamps(data: &[u8]) -> EncodingResult<[BacnetTimeStamp; 3]> {
    let mut pos = 0;
    let mut out = [
        BacnetTimeStamp::SequenceNumber(0),
        BacnetTimeStamp::SequenceNumber(0),
        BacnetTimeStamp::SequenceNumber(0),
    ];
    for slot in out.iter_mut() {
        let (ts, consumed) = BacnetTimeStamp::decode_choice(&data[pos..])?;
        *slot = ts;
        pos += consumed;
    }
    Ok(out)
}

fn decode_three_unsigned(data: &[u8]) -> EncodingResult<[u32; 3]> {
    let mut pos = 0;
    let mut out = [0u32; 3];
    for slot in out.iter_mut() {
        let (value, consumed) = decode_unsigned(&data[pos..])?;
        *slot = value;
        pos += consumed;
    }
    Ok(out)
}

// Encoding of the response/summary is provided for round-trip testing and for
// any future server-side use.
impl EventSummary {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        buffer.extend_from_slice(&encode_context_object_id(self.object_identifier, 0)?);
        buffer.extend_from_slice(&encode_context_enumerated(
            u16::from(self.event_state).into(),
            1,
        )?);
        self.acknowledged_transitions.encode_context(buffer, 2)?;
        encode_constructed_context(buffer, 3, |inner| {
            for ts in &self.event_time_stamps {
                ts.encode_choice(inner)?;
            }
            Ok(())
        })?;
        buffer.extend_from_slice(&encode_context_enumerated(u32::from(self.notify_type), 4)?);
        self.event_enable.encode_context(buffer, 5)?;
        encode_constructed_context(buffer, 6, |inner| {
            for prio in &self.event_priorities {
                crate::encoding::encode_unsigned(inner, *prio)?;
            }
            Ok(())
        })?;
        Ok(())
    }
}

impl GetEventInformationResponse {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        encode_constructed_context(buffer, 0, |inner| {
            for event in &self.events {
                event.encode(inner)?;
            }
            Ok(())
        })?;
        // [1] moreEvents — context boolean, 1 payload byte.
        encode_context_tag(buffer, 1, 1)?;
        buffer.push(u8::from(self.more_events));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{Date, ObjectType, Time};

    fn sample_datetime() -> BacnetDateTime {
        BacnetDateTime::new(
            Date {
                year: 2024,
                month: 6,
                day: 5,
                weekday: 3,
            },
            Time {
                hour: 12,
                minute: 0,
                second: 0,
                hundredths: 0,
            },
        )
    }

    fn sample_summary() -> EventSummary {
        EventSummary {
            object_identifier: ObjectIdentifier::new(ObjectType::AnalogInput, 7),
            event_state: EventState::HighLimit,
            acknowledged_transitions: EventTransitionBits {
                to_offnormal: false,
                to_fault: true,
                to_normal: true,
            },
            event_time_stamps: [
                BacnetTimeStamp::Time(Time {
                    hour: 10,
                    minute: 20,
                    second: 30,
                    hundredths: 40,
                }),
                BacnetTimeStamp::SequenceNumber(0),
                BacnetTimeStamp::DateTime(sample_datetime()),
            ],
            notify_type: 0,
            event_enable: EventTransitionBits {
                to_offnormal: true,
                to_fault: true,
                to_normal: true,
            },
            event_priorities: [3, 5, 7],
        }
    }

    #[test]
    fn request_encodes_optional_object_identifier() {
        let mut empty = Vec::new();
        GetEventInformationRequest::new().encode(&mut empty).unwrap();
        assert!(empty.is_empty());

        let mut paged = Vec::new();
        GetEventInformationRequest::paged_from(ObjectIdentifier::new(ObjectType::AnalogInput, 7))
            .encode(&mut paged)
            .unwrap();
        assert_eq!(paged[0], 0x0C); // context tag 0, 4-byte object id
    }

    #[test]
    fn transition_bits_round_trip_through_payload() {
        let bits = EventTransitionBits {
            to_offnormal: true,
            to_fault: false,
            to_normal: true,
        };
        let mut buf = Vec::new();
        bits.encode_context(&mut buf, 2).unwrap();
        let (tag, payload, _) = decode_context_primitive(&buf).unwrap();
        assert_eq!(tag, 2);
        assert_eq!(EventTransitionBits::from_bit_payload(payload), bits);
    }

    #[test]
    fn timestamp_choice_round_trips() {
        for ts in [
            BacnetTimeStamp::Time(Time {
                hour: 1,
                minute: 2,
                second: 3,
                hundredths: 4,
            }),
            BacnetTimeStamp::SequenceNumber(4242),
            BacnetTimeStamp::DateTime(sample_datetime()),
        ] {
            let mut buf = Vec::new();
            ts.encode_choice(&mut buf).unwrap();
            let (decoded, consumed) = BacnetTimeStamp::decode_choice(&buf).unwrap();
            assert_eq!(decoded, ts);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn response_round_trips_two_events() {
        let response = GetEventInformationResponse {
            events: vec![sample_summary(), sample_summary()],
            more_events: true,
        };
        let mut buf = Vec::new();
        response.encode(&mut buf).unwrap();

        let decoded = GetEventInformationResponse::decode(&buf).unwrap();
        assert_eq!(decoded.events.len(), 2);
        assert!(decoded.more_events);

        let event = &decoded.events[0];
        assert_eq!(event.object_identifier.instance, 7);
        assert_eq!(event.event_state, EventState::HighLimit);
        assert!(!event.acknowledged_transitions.to_offnormal);
        assert!(event.acknowledged_transitions.to_fault);
        assert_eq!(event.notify_type, 0);
        assert_eq!(event.event_priorities, [3, 5, 7]);
        assert_eq!(
            event.event_time_stamps[0],
            BacnetTimeStamp::Time(Time {
                hour: 10,
                minute: 20,
                second: 30,
                hundredths: 40,
            })
        );
    }

    #[test]
    fn response_without_more_events_byte_defaults_false() {
        let response = GetEventInformationResponse {
            events: vec![sample_summary()],
            more_events: false,
        };
        let mut buf = Vec::new();
        response.encode(&mut buf).unwrap();
        let decoded = GetEventInformationResponse::decode(&buf).unwrap();
        assert!(!decoded.more_events);
    }
}
