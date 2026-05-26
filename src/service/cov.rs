//! BACnet UnconfirmedCOVNotification service (service choice 2).
//!
//! Encodes/decodes the COV notification PDU. SubscribeCOV request encoding
//! lives on [`SubscribeCovRequest`](super::SubscribeCovRequest); this module
//! covers the notification side, which bacnet-rs previously left as a stub.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use crate::encoding::{
    decode_context_object_id, decode_context_unsigned, decode_tag_header, extract_context_block,
    EncodingError, Result as EncodingResult,
};
use crate::object::ObjectIdentifier;
use crate::property::{decode_property_value, PropertyValue};

/// One `(property_id, value)` entry in a COV notification's `listOfValues`.
#[derive(Debug, Clone)]
pub struct CovPropertyValue {
    pub property_identifier: u32,
    pub property_array_index: Option<u32>,
    /// One or more application-tagged values from the propertyValue block.
    pub values: Vec<PropertyValue>,
    /// Optional priority (1..16) when the notification originates from a
    /// commandable object.
    pub priority: Option<u32>,
}

/// Decoded UnconfirmedCOVNotification service data.
#[derive(Debug, Clone)]
pub struct CovNotification {
    pub subscriber_process_identifier: u32,
    pub initiating_device: ObjectIdentifier,
    pub monitored_object: ObjectIdentifier,
    pub time_remaining: u32,
    pub list_of_values: Vec<CovPropertyValue>,
}

impl CovNotification {
    /// Decode the service body (no PDU type byte, no service-choice byte).
    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut pos = 0;

        let (subscriber_process_identifier, consumed) =
            decode_context_unsigned(data_at(data, pos)?, 0)?;
        pos += consumed;

        let (initiating_device, consumed) =
            decode_context_object_id(data_at(data, pos)?, 1)?;
        pos += consumed;

        let (monitored_object, consumed) =
            decode_context_object_id(data_at(data, pos)?, 2)?;
        pos += consumed;

        let (time_remaining, consumed) = decode_context_unsigned(data_at(data, pos)?, 3)?;
        pos += consumed;

        // [4] listOfValues: constructed context block.
        let (list_bytes, _) = extract_context_block(data_at(data, pos)?, 4)?;
        let list_of_values = decode_list_of_values(list_bytes)?;

        Ok(CovNotification {
            subscriber_process_identifier,
            initiating_device,
            monitored_object,
            time_remaining,
            list_of_values,
        })
    }
}

fn data_at(data: &[u8], pos: usize) -> EncodingResult<&[u8]> {
    data.get(pos..).ok_or(EncodingError::UnexpectedEndOfData)
}

fn decode_list_of_values(mut data: &[u8]) -> EncodingResult<Vec<CovPropertyValue>> {
    let mut entries = Vec::new();
    while !data.is_empty() {
        let (entry, consumed) = decode_property_value_entry(data)?;
        if consumed == 0 {
            return Err(EncodingError::InvalidFormat(
                "COV property entry produced no progress".into(),
            ));
        }
        entries.push(entry);
        data = &data[consumed..];
    }
    Ok(entries)
}

fn decode_property_value_entry(data: &[u8]) -> EncodingResult<(CovPropertyValue, usize)> {
    let mut pos = 0;

    // [0] propertyIdentifier
    let (property_identifier, consumed) = decode_context_unsigned(data, 0)?;
    pos += consumed;

    // [1] propertyArrayIndex (optional)
    let property_array_index = if is_primitive_with_tag(&data[pos..], 1) {
        let (index, consumed) = decode_context_unsigned(&data[pos..], 1)?;
        pos += consumed;
        Some(index)
    } else {
        None
    };

    // [2] propertyValue: constructed.
    let (value_bytes, consumed) = extract_context_block(&data[pos..], 2)?;
    pos += consumed;
    let values = decode_application_values(value_bytes)?;

    // [3] priority (optional)
    let priority = if is_primitive_with_tag(&data[pos..], 3) {
        let (p, consumed) = decode_context_unsigned(&data[pos..], 3)?;
        pos += consumed;
        Some(p)
    } else {
        None
    };

    Ok((
        CovPropertyValue {
            property_identifier,
            property_array_index,
            values,
            priority,
        },
        pos,
    ))
}

fn decode_application_values(mut data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
    let mut values = Vec::new();
    while !data.is_empty() {
        let (value, consumed) = decode_property_value(data)?;
        if consumed == 0 {
            return Err(EncodingError::InvalidFormat(
                "COV value decoder produced no progress".into(),
            ));
        }
        values.push(value);
        data = &data[consumed..];
    }
    Ok(values)
}

fn is_primitive_with_tag(data: &[u8], tag: u8) -> bool {
    matches!(
        decode_tag_header(data),
        Ok(header) if header.is_context() && header.is_primitive() && header.tag_number == tag
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{encode_context_object_id, encode_context_unsigned, encode_real};
    use crate::object::ObjectType;

    fn build_notification_body(
        process_id: u32,
        device_instance: u32,
        monitored_type: ObjectType,
        monitored_instance: u32,
        time_remaining: u32,
        present_value: f32,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&encode_context_unsigned(process_id, 0).unwrap());
        body.extend_from_slice(
            &encode_context_object_id(
                ObjectIdentifier::new(ObjectType::Device, device_instance),
                1,
            )
            .unwrap(),
        );
        body.extend_from_slice(
            &encode_context_object_id(
                ObjectIdentifier::new(monitored_type, monitored_instance),
                2,
            )
            .unwrap(),
        );
        body.extend_from_slice(&encode_context_unsigned(time_remaining, 3).unwrap());

        body.push(0x4E); // [4] opening
        body.extend_from_slice(&encode_context_unsigned(85, 0).unwrap());
        body.push(0x2E); // [2] opening
        let mut real = Vec::new();
        encode_real(&mut real, present_value).unwrap();
        body.extend_from_slice(&real);
        body.push(0x2F); // [2] closing
        body.push(0x4F); // [4] closing
        body
    }

    #[test]
    fn decode_extracts_header_and_value() {
        let body = build_notification_body(1, 10, ObjectType::AnalogInput, 5, 42, 73.5);
        let notif = CovNotification::decode(&body).unwrap();

        assert_eq!(notif.subscriber_process_identifier, 1);
        assert_eq!(notif.initiating_device.instance, 10);
        assert_eq!(notif.monitored_object.object_type, ObjectType::AnalogInput);
        assert_eq!(notif.monitored_object.instance, 5);
        assert_eq!(notif.time_remaining, 42);

        assert_eq!(notif.list_of_values.len(), 1);
        let entry = &notif.list_of_values[0];
        assert_eq!(entry.property_identifier, 85);
        assert!(entry.property_array_index.is_none());
        assert_eq!(entry.values.len(), 1);
        match entry.values[0] {
            PropertyValue::Real(v) => assert!((v - 73.5).abs() < 1e-6),
            ref other => panic!("expected Real, got {:?}", other),
        }
        assert!(entry.priority.is_none());
    }

    #[test]
    fn decode_handles_property_array_index_and_priority() {
        let mut body = Vec::new();
        body.extend_from_slice(&encode_context_unsigned(7, 0).unwrap());
        body.extend_from_slice(
            &encode_context_object_id(ObjectIdentifier::new(ObjectType::Device, 99), 1).unwrap(),
        );
        body.extend_from_slice(
            &encode_context_object_id(ObjectIdentifier::new(ObjectType::BinaryOutput, 3), 2)
                .unwrap(),
        );
        body.extend_from_slice(&encode_context_unsigned(10, 3).unwrap());

        body.push(0x4E); // [4] opening
        body.extend_from_slice(&encode_context_unsigned(85, 0).unwrap()); // propertyId
        body.extend_from_slice(&encode_context_unsigned(2, 1).unwrap()); // arrayIndex
        body.push(0x2E); // [2] opening
        let mut real = Vec::new();
        encode_real(&mut real, 1.5).unwrap();
        body.extend_from_slice(&real);
        body.push(0x2F); // [2] closing
        body.extend_from_slice(&encode_context_unsigned(8, 3).unwrap()); // priority
        body.push(0x4F); // [4] closing

        let notif = CovNotification::decode(&body).unwrap();
        let entry = &notif.list_of_values[0];
        assert_eq!(entry.property_array_index, Some(2));
        assert_eq!(entry.priority, Some(8));
    }

    #[test]
    fn decode_collects_multiple_entries() {
        let mut body = Vec::new();
        body.extend_from_slice(&encode_context_unsigned(1, 0).unwrap());
        body.extend_from_slice(
            &encode_context_object_id(ObjectIdentifier::new(ObjectType::Device, 1), 1).unwrap(),
        );
        body.extend_from_slice(
            &encode_context_object_id(ObjectIdentifier::new(ObjectType::AnalogInput, 2), 2)
                .unwrap(),
        );
        body.extend_from_slice(&encode_context_unsigned(60, 3).unwrap());

        body.push(0x4E);
        // entry 1: propertyId 85, real 1.0
        body.extend_from_slice(&encode_context_unsigned(85, 0).unwrap());
        body.push(0x2E);
        let mut real = Vec::new();
        encode_real(&mut real, 1.0).unwrap();
        body.extend_from_slice(&real);
        body.push(0x2F);
        // entry 2: propertyId 111, real 0.0
        body.extend_from_slice(&encode_context_unsigned(111, 0).unwrap());
        body.push(0x2E);
        let mut real = Vec::new();
        encode_real(&mut real, 0.0).unwrap();
        body.extend_from_slice(&real);
        body.push(0x2F);
        body.push(0x4F);

        let notif = CovNotification::decode(&body).unwrap();
        assert_eq!(notif.list_of_values.len(), 2);
        assert_eq!(notif.list_of_values[0].property_identifier, 85);
        assert_eq!(notif.list_of_values[1].property_identifier, 111);
    }

    #[test]
    fn subscribe_cov_encode_uses_variable_length_lifetime() {
        // 70_000 needs 3 payload bytes, so the [3] tag should report length 3.
        use super::super::SubscribeCovRequest;
        let req = SubscribeCovRequest {
            subscriber_process_identifier: 1,
            monitored_object_identifier: ObjectIdentifier::new(ObjectType::AnalogInput, 5),
            issue_confirmed_notifications: Some(false),
            lifetime: Some(70_000),
        };
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();

        // Look for the [3] lifetime tag — variable-length unsigned must be 3 bytes,
        // so the tag byte is (3 << 4) | 0x08 | 0x03 = 0x3B, followed by 3 bytes.
        assert!(buf.windows(4).any(|w| w == [0x3B, 0x01, 0x11, 0x70]));
    }

    #[test]
    fn subscribe_cov_encode_cancel_form_omits_lifetime_and_confirmed() {
        use super::super::SubscribeCovRequest;
        let req = SubscribeCovRequest::new(
            42,
            ObjectIdentifier::new(ObjectType::AnalogInput, 5),
        );
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();

        // Cancel form: only [0] and [1] tags. There must be no [2] or [3] tags
        // (context-primitive: tag byte's low bit set for context, tag number
        // in top nibble). [2]* tags begin with 0x2X..0x29; [3]* with 0x3X..0x39.
        // A simpler invariant: cancel-form body must be short.
        assert!(buf.len() <= 7, "expected short cancel form, got {buf:?}");
    }

    #[test]
    fn subscribe_cov_encode_uses_explicit_boolean_form() {
        use super::super::SubscribeCovRequest;
        let req = SubscribeCovRequest::with_confirmation(
            1,
            ObjectIdentifier::new(ObjectType::AnalogInput, 5),
            false,
        );
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();

        // Explicit-length boolean for tag 2: tag byte 0x29 (context 2, len 1),
        // payload 0x00 for false.
        assert!(buf.windows(2).any(|w| w == [0x29, 0x00]));
    }
}
