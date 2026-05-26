//! BACnet ReadRange confirmed service (service choice 26).
//!
//! Encodes [`ReadRangeRequest`] and decodes [`ReadRangeResponse`] including the
//! per-record `BACnetLogRecord` structure (timestamp, log datum, status flags)
//! defined in clause 21 of ASHRAE 135.

#[cfg(not(feature = "std"))]
use alloc::{format, vec, vec::Vec};

use crate::encoding::{
    bytes_to_signed, bytes_to_unsigned, decode_context_primitive, decode_context_unsigned,
    decode_tag_header, encode_constructed_context, encode_context_enumerated,
    encode_context_object_id, encode_context_signed, encode_context_unsigned, extract_context_block,
    skip_value, EncodingError, Result as EncodingResult,
};
use crate::object::{ObjectIdentifier, PropertyIdentifier};
use crate::property::{decode_property_value, PropertyValue};
use crate::service::BacnetDateTime;

/// Range specifier for a ReadRange request.
///
/// BACnet defines additional `byTime` variants ([3] byPosition, [6] bySequenceNumber,
/// [7] byTime); only the two currently used by bacr8 are exposed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadRangeBy {
    /// Read `count` records starting at `reference_index` (1-based position).
    /// Negative count reads backwards from the reference.
    Position { reference_index: u32, count: i32 },
    /// Read `count` records starting at sequence number `reference_index`.
    Sequence { reference_index: u32, count: i32 },
}

/// ReadRange-Request (confirmed service 26).
#[derive(Debug, Clone)]
pub struct ReadRangeRequest {
    pub object_identifier: ObjectIdentifier,
    pub property_identifier: PropertyIdentifier,
    pub property_array_index: Option<u32>,
    pub range: Option<ReadRangeBy>,
}

impl ReadRangeRequest {
    pub fn new(
        object_identifier: ObjectIdentifier,
        property_identifier: PropertyIdentifier,
    ) -> Self {
        Self {
            object_identifier,
            property_identifier,
            property_array_index: None,
            range: None,
        }
    }

    pub fn with_range(mut self, range: ReadRangeBy) -> Self {
        self.range = Some(range);
        self
    }

    /// Encode the request body (no service-choice prefix).
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        // [0] objectIdentifier
        buffer.extend_from_slice(&encode_context_object_id(self.object_identifier, 0)?);

        // [1] propertyIdentifier
        buffer.extend_from_slice(&encode_context_enumerated(
            self.property_identifier.into(),
            1,
        )?);

        // [2] propertyArrayIndex (optional)
        if let Some(index) = self.property_array_index {
            buffer.extend_from_slice(&encode_context_unsigned(index, 2)?);
        }

        // [3]/[6] range specifier (optional). Omitting returns all records up
        // to the APDU limit.
        if let Some(range) = self.range {
            let tag = match range {
                ReadRangeBy::Position { .. } => 3,
                ReadRangeBy::Sequence { .. } => 6,
            };
            let (reference_index, count) = match range {
                ReadRangeBy::Position {
                    reference_index,
                    count,
                }
                | ReadRangeBy::Sequence {
                    reference_index,
                    count,
                } => (reference_index, count),
            };
            encode_constructed_context(buffer, tag, |inner| {
                inner.extend_from_slice(&encode_context_unsigned(reference_index, 0)?);
                inner.extend_from_slice(&encode_context_signed(i64::from(count), 1)?);
                Ok(())
            })?;
        }

        Ok(())
    }
}

/// Result flags from a ReadRange-ACK ([3] resultFlags).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResultFlags {
    pub first_item: bool,
    pub last_item: bool,
    pub more_items: bool,
}

/// One decoded BACnetLogRecord.
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub timestamp: BacnetDateTime,
    pub datum: LogDatum,
    /// BACnet status-flags at time of recording. Standard order:
    /// [in_alarm, fault, overridden, out_of_service]. May be empty or shorter
    /// when devices truncate trailing zero bits.
    pub status_flags: Option<Vec<bool>>,
}

/// The `logDatum` CHOICE field of a BACnetLogRecord.
#[derive(Debug, Clone)]
pub enum LogDatum {
    /// [0] logStatus: BIT STRING with `log-disabled`, `buffer-purged`,
    /// `log-interrupted` bits.
    LogStatus(Vec<bool>),
    /// [1]..[7] inline value: primitive context-tagged datum mapped to
    /// the equivalent application value.
    Value(PropertyValue),
    /// [8] logFailure: an Error PDU shape (errorClass, errorCode).
    Failure { error_class: u32, error_code: u32 },
    /// [9] timeChange: REAL delta seconds since the previous record.
    TimeChange(f32),
    /// [10] anyValue: zero or more application-tagged values.
    AnyValue(Vec<PropertyValue>),
    /// Datum we could not interpret (raw bytes, including the tag header).
    Unknown(Vec<u8>),
}

/// ReadRange-ACK.
#[derive(Debug, Clone)]
pub struct ReadRangeResponse {
    pub object_identifier: ObjectIdentifier,
    pub property_identifier: PropertyIdentifier,
    pub property_array_index: Option<u32>,
    pub result_flags: ResultFlags,
    pub item_count: u32,
    pub records: Vec<LogRecord>,
    pub first_sequence_number: Option<u32>,
}

impl ReadRangeResponse {
    /// Decode a ReadRange-ACK service body (without the leading service-choice
    /// byte — strip it at the APDU layer).
    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut pos = 0;

        // [0] objectIdentifier — encoded as a 4-byte context primitive
        // (tag = 0x0C). Use the high-level helper rather than rolling our own.
        let (object_identifier, consumed) = decode_context_object_id_at(data, &mut pos, 0)?;
        let _ = (consumed, object_identifier);

        // [1] propertyIdentifier
        let property_id_u32 = decode_primitive_unsigned(data, &mut pos, 1)?;

        // [2] propertyArrayIndex (optional)
        let property_array_index = if is_context_primitive(data, pos, 2) {
            Some(decode_primitive_unsigned(data, &mut pos, 2)?)
        } else {
            None
        };

        // [3] resultFlags: context primitive BIT STRING. Tag header byte
        // followed by `unused_bits` then the flag byte.
        let result_flags = decode_result_flags(data, &mut pos)?;

        // [4] itemCount
        let item_count = decode_primitive_unsigned(data, &mut pos, 4)?;

        // [5] itemData: constructed context block (opening tag 5) containing
        // `item_count` BACnetLogRecord structures.
        //
        // Note: the wire encoding actually uses opening tag 5 / closing tag 5
        // (0x5E / 0x5F). The previous bacr8 implementation matched
        // `0x0E`/opening tag 0 because the slice it received still included
        // the service choice byte; with the service prefix stripped, this is
        // the correct tag. We probe both to remain tolerant of either input
        // shape during the migration.
        let (item_data, consumed) = match read_context_block(data, pos, 5) {
            Ok(value) => value,
            Err(_) => read_context_block(data, pos, 0)?,
        };
        pos += consumed;

        let records = decode_log_records(item_data, item_count as usize)?;

        // [6] firstSequenceNumber (optional)
        let first_sequence_number = if is_context_primitive(data, pos, 6) {
            Some(decode_primitive_unsigned(data, &mut pos, 6)?)
        } else {
            None
        };

        Ok(ReadRangeResponse {
            object_identifier,
            property_identifier: property_id_u32.into(),
            property_array_index,
            result_flags,
            item_count,
            records,
            first_sequence_number,
        })
    }
}

fn is_context_primitive(data: &[u8], pos: usize, tag: u8) -> bool {
    let Some(remaining) = data.get(pos..) else {
        return false;
    };
    matches!(
        decode_tag_header(remaining),
        Ok(header) if header.is_context()
            && header.is_primitive()
            && header.tag_number == tag
    )
}

fn decode_primitive_unsigned(data: &[u8], pos: &mut usize, tag: u8) -> EncodingResult<u32> {
    let remaining = data.get(*pos..).ok_or(EncodingError::UnexpectedEndOfData)?;
    let (value, consumed) = decode_context_unsigned(remaining, tag)?;
    *pos += consumed;
    Ok(value)
}

fn decode_context_object_id_at(
    data: &[u8],
    pos: &mut usize,
    tag: u8,
) -> EncodingResult<(ObjectIdentifier, usize)> {
    use crate::encoding::decode_context_object_id;

    let remaining = data.get(*pos..).ok_or(EncodingError::UnexpectedEndOfData)?;
    let (oid, consumed) = decode_context_object_id(remaining, tag)?;
    *pos += consumed;
    Ok((oid, consumed))
}

fn read_context_block(data: &[u8], pos: usize, tag: u8) -> EncodingResult<(&[u8], usize)> {
    let remaining = data.get(pos..).ok_or(EncodingError::UnexpectedEndOfData)?;
    extract_context_block(remaining, tag)
}

fn decode_result_flags(data: &[u8], pos: &mut usize) -> EncodingResult<ResultFlags> {
    let remaining = data.get(*pos..).ok_or(EncodingError::UnexpectedEndOfData)?;
    let (tag, payload, consumed) = decode_context_primitive(remaining)?;
    if tag != 3 {
        return Err(EncodingError::InvalidTag);
    }
    *pos += consumed;
    // BIT STRING payload: first byte = unused_bits, remaining bytes = bits MSB-first.
    let flags = ResultFlags {
        first_item: bit(payload, 1, 7),
        last_item: bit(payload, 1, 6),
        more_items: bit(payload, 1, 5),
    };
    Ok(flags)
}

fn bit(payload: &[u8], byte_index: usize, bit_index_msb: u8) -> bool {
    payload
        .get(byte_index)
        .map(|byte| (byte >> bit_index_msb) & 1 == 1)
        .unwrap_or(false)
}

fn decode_log_records(data: &[u8], _expected_count: usize) -> EncodingResult<Vec<LogRecord>> {
    let mut records = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        // Each record begins with [0] OPENING for the timestamp.
        let header = match decode_tag_header(&data[pos..]) {
            Ok(h) => h,
            Err(_) => {
                pos += 1;
                continue;
            }
        };
        if !(header.is_opening() && header.tag_number == 0) {
            // Skip unexpected tag conservatively.
            let consumed = skip_value(&data[pos..]).unwrap_or(1).max(1);
            pos += consumed;
            continue;
        }

        // [0] timestamp block: BACnetDateTime (application Date + Time).
        let (ts_data, consumed) = extract_context_block(&data[pos..], 0)?;
        pos += consumed;
        let (timestamp, _) = BacnetDateTime::decode(ts_data)?;

        // [1] logDatum block.
        let (datum_data, consumed) = extract_context_block(&data[pos..], 1)?;
        pos += consumed;
        let datum = decode_log_datum(datum_data);

        // [2] statusFlags (optional, context primitive BIT STRING).
        let status_flags = if is_context_primitive(data, pos, 2) {
            let (_, payload, consumed) = decode_context_primitive(&data[pos..])?;
            pos += consumed;
            Some(decode_bit_string_payload(payload))
        } else {
            None
        };

        records.push(LogRecord {
            timestamp,
            datum,
            status_flags,
        });
    }

    Ok(records)
}

fn decode_log_datum(data: &[u8]) -> LogDatum {
    if data.is_empty() {
        return LogDatum::Unknown(Vec::new());
    }

    let Ok(header) = decode_tag_header(data) else {
        return LogDatum::Unknown(data.to_vec());
    };

    if !header.is_context() {
        // Non-context tag — try to decode as an application value.
        return match decode_property_value(data) {
            Ok((value, _)) => LogDatum::Value(value),
            Err(_) => LogDatum::Unknown(data.to_vec()),
        };
    }

    let tag = header.tag_number;

    if header.is_opening() {
        return match tag {
            8 => decode_failure_block(data),
            10 => decode_any_value_block(data),
            _ => LogDatum::Unknown(data.to_vec()),
        };
    }

    if header.is_closing() {
        return LogDatum::Unknown(data.to_vec());
    }

    let Ok((_, payload, _)) = decode_context_primitive(data) else {
        return LogDatum::Unknown(data.to_vec());
    };

    match tag {
        0 => LogDatum::LogStatus(decode_bit_string_payload(payload)),
        1 => LogDatum::Value(PropertyValue::Boolean(
            payload.first().copied().unwrap_or(0) != 0,
        )),
        2 => {
            if payload.len() < 4 {
                LogDatum::Unknown(data.to_vec())
            } else {
                LogDatum::Value(PropertyValue::Real(f32::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ])))
            }
        }
        3 => match bytes_to_unsigned(payload) {
            Ok(value) => LogDatum::Value(PropertyValue::Enumerated(value as u32)),
            Err(_) => LogDatum::Unknown(data.to_vec()),
        },
        4 => match bytes_to_unsigned(payload) {
            Ok(value) => LogDatum::Value(PropertyValue::Unsigned(value)),
            Err(_) => LogDatum::Unknown(data.to_vec()),
        },
        5 => match bytes_to_signed(payload) {
            Ok(value) => LogDatum::Value(PropertyValue::Signed(value)),
            Err(_) => LogDatum::Unknown(data.to_vec()),
        },
        6 => LogDatum::Value(PropertyValue::BitString(decode_bit_string_payload(payload))),
        7 => LogDatum::Value(PropertyValue::Null),
        9 => {
            if payload.len() < 4 {
                LogDatum::Unknown(data.to_vec())
            } else {
                LogDatum::TimeChange(f32::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]))
            }
        }
        _ => LogDatum::Unknown(data.to_vec()),
    }
}

fn decode_failure_block(data: &[u8]) -> LogDatum {
    let Ok((content, _)) = extract_context_block(data, 8) else {
        return LogDatum::Unknown(data.to_vec());
    };
    let (error_class, consumed) = decode_app_unsigned(content, 0);
    let (error_code, _) = decode_app_unsigned(content, consumed);
    LogDatum::Failure {
        error_class,
        error_code,
    }
}

fn decode_any_value_block(data: &[u8]) -> LogDatum {
    let Ok((content, _)) = extract_context_block(data, 10) else {
        return LogDatum::Unknown(data.to_vec());
    };
    let mut cursor = content;
    let mut values = Vec::new();
    while !cursor.is_empty() {
        match decode_property_value(cursor) {
            Ok((value, consumed)) if consumed > 0 => {
                values.push(value);
                cursor = &cursor[consumed..];
            }
            _ => return LogDatum::Unknown(data.to_vec()),
        }
    }
    LogDatum::AnyValue(values)
}

fn decode_bit_string_payload(payload: &[u8]) -> Vec<bool> {
    if payload.is_empty() {
        return Vec::new();
    }
    let unused = payload[0] as usize;
    let bit_bytes = &payload[1..];
    let total = bit_bytes.len() * 8;
    let used = total.saturating_sub(unused);
    bit_bytes
        .iter()
        .flat_map(|byte| (0..8u8).rev().map(move |i| (byte >> i) & 1 == 1))
        .take(used)
        .collect()
}

/// Decode an application-tagged unsigned integer at `pos`. Returns (value, consumed).
fn decode_app_unsigned(data: &[u8], pos: usize) -> (u32, usize) {
    let Some(&tag) = data.get(pos) else {
        return (0, 0);
    };
    let len = (tag & 0x07) as usize;
    if data.len() < pos + 1 + len {
        return (0, 1);
    }
    let value = bytes_to_unsigned(&data[pos + 1..pos + 1 + len])
        .ok()
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    (value, 1 + len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;

    #[test]
    fn encode_context_signed_one_byte_positive() {
        let bytes = encode_context_signed(10, 1).unwrap();
        assert_eq!(bytes, vec![0x19, 10]);
    }

    #[test]
    fn encode_context_signed_one_byte_negative() {
        let bytes = encode_context_signed(-1, 1).unwrap();
        assert_eq!(bytes, vec![0x19, 0xFF]);
    }

    #[test]
    fn encode_context_signed_two_byte_negative() {
        let bytes = encode_context_signed(-200, 1).unwrap();
        assert_eq!(bytes[0], 0x1A);
        let val = i16::from_be_bytes([bytes[1], bytes[2]]);
        assert_eq!(val, -200);
    }

    fn encode_for_test(
        object_type: ObjectType,
        instance: u32,
        property_id: u32,
        range: Option<ReadRangeBy>,
    ) -> Vec<u8> {
        let mut req = ReadRangeRequest::new(
            ObjectIdentifier::new(object_type, instance),
            PropertyIdentifier::from(property_id),
        );
        req.range = range;
        let mut buf = Vec::new();
        req.encode(&mut buf).expect("encode");
        buf
    }

    #[test]
    fn encode_read_range_omits_range_when_none() {
        let bytes = encode_for_test(ObjectType::TrendLog, 1, 131, None);
        assert!(!bytes.contains(&0x3E));
        assert!(!bytes.contains(&0x6E));
    }

    #[test]
    fn encode_read_range_preserves_large_property_ids() {
        let bytes = encode_for_test(ObjectType::TrendLog, 1, 70_000, None);
        assert!(bytes.windows(4).any(|window| window
            == [0x1B, 0x01, 0x11, 0x70]));
    }

    #[test]
    fn encode_read_range_by_position_includes_reference_and_count() {
        let bytes = encode_for_test(
            ObjectType::TrendLog,
            1,
            131,
            Some(ReadRangeBy::Position {
                reference_index: 7,
                count: -5,
            }),
        );
        assert!(bytes.windows(6).any(|window| window
            == [0x3E, 0x09, 0x07, 0x19, 0xFB, 0x3F]));
    }

    #[test]
    fn encode_read_range_by_sequence_includes_reference_and_count() {
        let bytes = encode_for_test(
            ObjectType::TrendLog,
            1,
            131,
            Some(ReadRangeBy::Sequence {
                reference_index: 55,
                count: 10,
            }),
        );
        assert!(bytes.windows(6).any(|window| window
            == [0x6E, 0x09, 0x37, 0x19, 0x0A, 0x6F]));
    }

    #[test]
    fn decode_log_datum_real_value() {
        let datum = decode_log_datum(&[0x2C, 0x3F, 0x80, 0x00, 0x00]);
        match datum {
            LogDatum::Value(PropertyValue::Real(f)) => assert!((f - 1.0).abs() < 1e-6),
            other => panic!("expected Real(1.0), got {:?}", other),
        }
    }

    #[test]
    fn decode_log_datum_null_value() {
        let datum = decode_log_datum(&[0x78]);
        assert!(matches!(datum, LogDatum::Value(PropertyValue::Null)));
    }

    #[test]
    fn decode_log_datum_boolean_true() {
        let datum = decode_log_datum(&[0x19, 0x01]);
        assert!(matches!(datum, LogDatum::Value(PropertyValue::Boolean(true))));
    }

    #[test]
    fn decode_log_datum_integer_negative() {
        let datum = decode_log_datum(&[0x59, 0xFF]);
        assert!(matches!(datum, LogDatum::Value(PropertyValue::Signed(-1))));
    }

    #[test]
    fn decode_log_datum_any_value_character_string() {
        // [10] anyValue containing application character-string "OK".
        let datum = decode_log_datum(&[0xAE, 0x73, 0x00, b'O', b'K', 0xAF]);
        match datum {
            LogDatum::AnyValue(values) => {
                assert_eq!(values.len(), 1);
                assert!(matches!(
                    values[0],
                    PropertyValue::CharacterString(ref s) if s == "OK"
                ));
            }
            other => panic!("expected AnyValue, got {:?}", other),
        }
    }

    #[test]
    fn decode_log_datum_any_value_multiple_values() {
        // [10] anyValue containing application unsigned 42 and boolean true.
        let datum = decode_log_datum(&[0xAE, 0x21, 0x2A, 0x11, 0xAF]);
        match datum {
            LogDatum::AnyValue(values) => {
                assert_eq!(values.len(), 2);
                assert!(matches!(values[0], PropertyValue::Unsigned(42)));
                assert!(matches!(values[1], PropertyValue::Boolean(true)));
            }
            other => panic!("expected AnyValue, got {:?}", other),
        }
    }

    #[test]
    fn decode_log_datum_unknown_keeps_full_raw_payload() {
        let datum = decode_log_datum(&[0xB9, 0x01]);
        match datum {
            LogDatum::Unknown(bytes) => assert_eq!(bytes, vec![0xB9, 0x01]),
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn decode_log_datum_time_change() {
        // [9] timeChange = 1.5 seconds
        let datum = decode_log_datum(&[0x9C, 0x3F, 0xC0, 0x00, 0x00]);
        match datum {
            LogDatum::TimeChange(delta) => assert!((delta - 1.5).abs() < 1e-6),
            other => panic!("expected TimeChange, got {:?}", other),
        }
    }

    #[test]
    fn decode_datetime_parses_date_and_time() {
        let data = [
            0xA4, 0x75, 0x01, 0x01, 0x01, // date: year=2017, month=1, day=1, weekday=Mon
            0xB4, 0x0C, 0x00, 0x00, 0x00, // time: 12:00:00.00
        ];
        let (dt, consumed) = BacnetDateTime::decode(&data).unwrap();
        assert_eq!(consumed, 10);
        assert_eq!(dt.date.year, 2017);
        assert_eq!(dt.date.month, 1);
        assert_eq!(dt.date.day, 1);
        assert_eq!(dt.time.hour, 12);
        assert_eq!(dt.time.minute, 0);
    }

    #[test]
    fn decode_read_range_response_one_real_record() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            // service-choice byte stripped by caller
            0x0C, 0x05, 0x00, 0x00, 0x01,                 // [0] objectIdentifier
            0x19, 0x83,                                    // [1] propertyIdentifier: 131
            0x3A, 0x05, 0xC0,                              // [3] resultFlags: first+last
            0x49, 0x01,                                    // [4] itemCount: 1
            0x5E,                                          // [5] OPENING itemData
                0x0E,                                      // [0] OPENING timestamp
                    0xA4, 0x75, 0x01, 0x01, 0x01,
                    0xB4, 0x0C, 0x00, 0x00, 0x00,
                0x0F,                                      // [0] CLOSING timestamp
                0x1E,                                      // [1] OPENING logDatum
                    0x2C, 0x3F, 0x80, 0x00, 0x00,         // [2] realValue 1.0
                0x1F,                                      // [1] CLOSING logDatum
            0x5F,                                          // [5] CLOSING itemData
        ];

        let result = ReadRangeResponse::decode(data).unwrap();
        assert_eq!(result.records.len(), 1);
        assert!(result.result_flags.first_item);
        assert!(result.result_flags.last_item);
        assert!(!result.result_flags.more_items);
        assert!(result.first_sequence_number.is_none());

        let rec = &result.records[0];
        assert_eq!(rec.timestamp.date.year, 2017);
        assert!(matches!(
            rec.datum,
            LogDatum::Value(PropertyValue::Real(f)) if (f - 1.0).abs() < 1e-6
        ));
        assert!(rec.status_flags.is_none());
    }

    #[test]
    fn decode_read_range_response_record_with_status_flags() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x0C, 0x05, 0x00, 0x00, 0x01,
            0x19, 0x83,
            0x3A, 0x05, 0xC0,
            0x49, 0x01,
            0x5E,
                0x0E,
                    0xA4, 0x75, 0x01, 0x01, 0x01,
                    0xB4, 0x00, 0x00, 0x00, 0x00,
                0x0F,
                0x1E,
                    0x78,                                  // [7] nullValue
                0x1F,
                0x2A, 0x04, 0x80,                          // [2] statusFlags: unused=4, in_alarm=1
            0x5F,
        ];

        let result = ReadRangeResponse::decode(data).unwrap();
        let sf = result.records[0].status_flags.clone().unwrap();
        assert!(sf.first().copied().unwrap_or(false)); // in_alarm
        assert!(sf.iter().skip(1).all(|b| !*b));
    }

    #[test]
    fn decode_read_range_response_tolerates_legacy_item_data_tag() {
        // Same payload as the success case but using the old 0x0E/0x0F opening
        // bytes that bacr8 previously produced when the service-choice byte was
        // still present. The decoder must accept either.
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x0C, 0x05, 0x00, 0x00, 0x01,
            0x19, 0x83,
            0x3A, 0x05, 0xC0,
            0x49, 0x01,
            0x0E,                                          // legacy itemData opening (tag 0)
                0x0E,
                    0xA4, 0x75, 0x01, 0x01, 0x01,
                    0xB4, 0x0C, 0x00, 0x00, 0x00,
                0x0F,
                0x1E,
                    0x2C, 0x3F, 0x80, 0x00, 0x00,
                0x1F,
            0x0F,                                          // legacy itemData closing
        ];

        let result = ReadRangeResponse::decode(data).unwrap();
        assert_eq!(result.records.len(), 1);
    }
}
