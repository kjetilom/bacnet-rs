//! BACnet AcknowledgeAlarm confirmed service (service choice 0).
//!
//! Encodes [`AcknowledgeAlarmRequest`] (clause 13.5 of ASHRAE 135). The
//! response is a SimpleACK with no body, so only the request is modelled here.
//! The `timeStamp` / `timeOfAcknowledgment` fields reuse the
//! [`BacnetTimeStamp`] CHOICE from [`crate::service::event_information`].

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::encoding::{
    encode_constructed_context, encode_context_enumerated, encode_context_object_id,
    encode_context_tag, encode_context_unsigned, Result as EncodingResult,
};
use crate::object::{EventState, ObjectIdentifier};
use crate::service::event_information::BacnetTimeStamp;

/// AcknowledgeAlarm-Request (confirmed service 0).
#[derive(Debug, Clone)]
pub struct AcknowledgeAlarmRequest {
    /// `acknowledgingProcessIdentifier [0]`.
    pub acknowledging_process_identifier: u32,
    /// `eventObjectIdentifier [1]`.
    pub event_object_identifier: ObjectIdentifier,
    /// `eventStateAcknowledged [2]` — the state whose transition is being acked.
    pub event_state_acknowledged: EventState,
    /// `timeStamp [3]` — timestamp of the transition being acknowledged, echoed
    /// from the notification / GetEventInformation summary.
    pub time_stamp: BacnetTimeStamp,
    /// `acknowledgmentSource [4]` — human/operator identifier.
    pub acknowledgment_source: String,
    /// `timeOfAcknowledgment [5]` — when the acknowledgment was issued.
    pub time_of_acknowledgment: BacnetTimeStamp,
}

impl AcknowledgeAlarmRequest {
    /// Encode the request body (no service-choice prefix).
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        // [0] acknowledgingProcessIdentifier
        buffer.extend_from_slice(&encode_context_unsigned(
            self.acknowledging_process_identifier,
            0,
        )?);

        // [1] eventObjectIdentifier
        buffer.extend_from_slice(&encode_context_object_id(self.event_object_identifier, 1)?);

        // [2] eventStateAcknowledged
        buffer.extend_from_slice(&encode_context_enumerated(
            u16::from(self.event_state_acknowledged).into(),
            2,
        )?);

        // [3] timeStamp — a CHOICE, so wrap it in the named element's tags.
        encode_constructed_context(buffer, 3, |inner| self.time_stamp.encode_choice(inner))?;

        // [4] acknowledgmentSource — context-tagged CharacterString
        // (encoding byte 0x00 = ANSI X3.4 / UTF-8, then the octets).
        let source = self.acknowledgment_source.as_bytes();
        encode_context_tag(buffer, 4, source.len() + 1)?;
        buffer.push(0x00);
        buffer.extend_from_slice(source);

        // [5] timeOfAcknowledgment
        encode_constructed_context(buffer, 5, |inner| {
            self.time_of_acknowledgment.encode_choice(inner)
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{ObjectType, Time};

    fn sample_request() -> AcknowledgeAlarmRequest {
        AcknowledgeAlarmRequest {
            acknowledging_process_identifier: 0,
            event_object_identifier: ObjectIdentifier::new(ObjectType::AnalogInput, 7),
            event_state_acknowledged: EventState::HighLimit,
            time_stamp: BacnetTimeStamp::Time(Time {
                hour: 10,
                minute: 20,
                second: 30,
                hundredths: 40,
            }),
            acknowledgment_source: "bacr8".to_string(),
            time_of_acknowledgment: BacnetTimeStamp::SequenceNumber(99),
        }
    }

    #[test]
    fn encodes_all_fields_in_tag_order() {
        let mut buf = Vec::new();
        sample_request().encode(&mut buf).unwrap();

        // [0] process id 0 -> context tag 0, len 1, value 0.
        assert_eq!(&buf[0..2], &[0x09, 0x00]);
        // [1] object identifier -> context tag 1, 4-byte object id.
        assert_eq!(buf[2], 0x1C);
        // The acknowledgment source octets must appear with the leading
        // character-set byte.
        assert!(buf.windows(6).any(|w| w == b"\x00bacr8"));
        // Opening/closing tags for the two timestamp CHOICE elements.
        assert!(buf.contains(&0x3E) && buf.contains(&0x3F)); // [3]
        assert!(buf.contains(&0x5E) && buf.contains(&0x5F)); // [5]
    }

    #[test]
    fn encodes_event_state_as_context_enumerated() {
        let mut buf = Vec::new();
        sample_request().encode(&mut buf).unwrap();
        // HighLimit = 3, context tag 2: 0x29, 0x03.
        assert!(buf.windows(2).any(|w| w == [0x29, 0x03]));
    }
}
