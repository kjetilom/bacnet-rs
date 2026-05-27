//! Recipient/destination datatypes: `Recipient_List` (102),
//! `Device_Address_Binding` (30) and `Active_COV_Subscriptions` (152).

use crate::datatypes::datetime::Time;
use crate::encoding::advanced::bitstring::{decode_bit_string, encode_bit_string};
use crate::encoding::{
    decode_boolean, decode_context_enumerated, decode_context_object_id, decode_context_primitive,
    decode_context_unsigned, decode_object_identifier, decode_octet_string, decode_tag_header,
    decode_unsigned, encode_boolean, encode_closing_tag, encode_context_object_id,
    encode_object_identifier, encode_octet_string, encode_opening_tag, encode_unsigned,
    Result as EncodingResult,
};
use crate::object::ObjectIdentifier;
use crate::EncodingError;

const DEVICE_OBJECT_TYPE: u32 = 8;

/// `BACnetAddress`: a network number and MAC address (empty MAC = broadcast).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacnetAddress {
    pub network_number: u16,
    pub mac_address: Vec<u8>,
}

impl BacnetAddress {
    fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        encode_unsigned(buffer, u32::from(self.network_number))?;
        encode_octet_string(buffer, &self.mac_address)
    }

    fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let (network, used) = decode_unsigned(data)?;
        let (mac, mac_used) = decode_octet_string(&data[used..])?;
        Ok((
            Self {
                network_number: u16::try_from(network).unwrap_or(u16::MAX),
                mac_address: mac,
            },
            used + mac_used,
        ))
    }
}

/// `BACnetRecipient` CHOICE: a device object or a network address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    Device { device_instance: u32 },
    Address(BacnetAddress),
}

impl Recipient {
    fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        match self {
            Recipient::Device { device_instance } => {
                let object_id = ObjectIdentifier::new(DEVICE_OBJECT_TYPE.into(), *device_instance);
                buffer.extend_from_slice(&encode_context_object_id(object_id, 0)?);
                Ok(())
            }
            Recipient::Address(address) => {
                encode_opening_tag(buffer, 1)?;
                address.encode(buffer)?;
                encode_closing_tag(buffer, 1)
            }
        }
    }

    fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let header = decode_tag_header(data)?;
        if !header.is_context() {
            return Err(EncodingError::InvalidTag);
        }
        match header.tag_number {
            0 => {
                let (object_id, consumed) = decode_context_object_id(data, 0)?;
                Ok((
                    Recipient::Device {
                        device_instance: object_id.instance,
                    },
                    consumed,
                ))
            }
            1 => {
                let (inner, consumed) =
                    crate::encoding::extract_context_block(data, 1)?;
                let (address, _) = BacnetAddress::decode(inner)?;
                Ok((Recipient::Address(address), consumed))
            }
            _ => Err(EncodingError::InvalidTag),
        }
    }
}

/// `BACnetDestination`: an entry in `Recipient_List`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// 7-bit BIT STRING, Monday..Sunday.
    pub valid_days: Vec<bool>,
    pub from_time: Time,
    pub to_time: Time,
    pub recipient: Recipient,
    pub process_identifier: u32,
    pub issue_confirmed_notifications: bool,
    /// 3-bit BIT STRING: to-offnormal, to-fault, to-normal.
    pub transitions: Vec<bool>,
}

impl Destination {
    fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        if self.valid_days.len() != 7 {
            return Err(EncodingError::InvalidFormat(
                "destination valid_days must contain exactly 7 bits".to_string(),
            ));
        }
        if self.transitions.len() != 3 {
            return Err(EncodingError::InvalidFormat(
                "destination transitions must contain exactly 3 bits".to_string(),
            ));
        }
        encode_bit_string(buffer, &self.valid_days)?;
        self.from_time.encode_application(buffer)?;
        self.to_time.encode_application(buffer)?;
        self.recipient.encode(buffer)?;
        encode_unsigned(buffer, self.process_identifier)?;
        encode_boolean(buffer, self.issue_confirmed_notifications)?;
        encode_bit_string(buffer, &self.transitions)?;
        Ok(())
    }

    fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let mut pos = 0;
        let (valid_days, used) = decode_bit_string(&data[pos..])?;
        pos += used;
        let (from_time, used) = Time::decode_application(&data[pos..])?;
        pos += used;
        let (to_time, used) = Time::decode_application(&data[pos..])?;
        pos += used;
        let (recipient, used) = Recipient::decode(&data[pos..])?;
        pos += used;
        let (process_identifier, used) = decode_unsigned(&data[pos..])?;
        pos += used;
        let (issue_confirmed_notifications, used) = decode_boolean(&data[pos..])?;
        pos += used;
        let (transitions, used) = decode_bit_string(&data[pos..])?;
        pos += used;
        Ok((
            Self {
                valid_days,
                from_time,
                to_time,
                recipient,
                process_identifier,
                issue_confirmed_notifications,
                transitions,
            },
            pos,
        ))
    }
}

/// `Recipient_List` (102): `LIST OF BACnetDestination`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecipientList {
    pub destinations: Vec<Destination>,
}

impl RecipientList {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        for destination in &self.destinations {
            destination.encode(buffer)?;
        }
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut destinations = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let (destination, consumed) = Destination::decode(&data[pos..])?;
            if consumed == 0 {
                return Err(EncodingError::InvalidFormat(
                    "destination made no progress".to_string(),
                ));
            }
            destinations.push(destination);
            pos += consumed;
        }
        Ok(Self { destinations })
    }
}

/// One `BACnetAddressBinding` (device id + its network address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressBinding {
    pub device_identifier: ObjectIdentifier,
    pub device_address: BacnetAddress,
}

impl AddressBinding {
    fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        encode_object_identifier(buffer, self.device_identifier)?;
        self.device_address.encode(buffer)
    }

    fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let (device_identifier, used) = decode_object_identifier(data)?;
        let (device_address, addr_used) = BacnetAddress::decode(&data[used..])?;
        Ok((
            Self {
                device_identifier,
                device_address,
            },
            used + addr_used,
        ))
    }
}

/// `Device_Address_Binding` (30): `LIST OF BACnetAddressBinding`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AddressBindingList {
    pub bindings: Vec<AddressBinding>,
}

impl AddressBindingList {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        for binding in &self.bindings {
            binding.encode(buffer)?;
        }
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut bindings = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let (binding, consumed) = AddressBinding::decode(&data[pos..])?;
            if consumed == 0 {
                return Err(EncodingError::InvalidFormat(
                    "address binding made no progress".to_string(),
                ));
            }
            bindings.push(binding);
            pos += consumed;
        }
        Ok(Self { bindings })
    }
}

/// `BACnetRecipientProcess`: a recipient plus a process identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientProcess {
    pub recipient: Recipient,
    pub process_identifier: u32,
}

/// `BACnetObjectPropertyReference`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPropertyReference {
    pub object_identifier: ObjectIdentifier,
    pub property_identifier: u32,
    pub property_array_index: Option<u32>,
}

/// `BACnetCOVSubscription`, an entry in `Active_COV_Subscriptions` (152).
///
/// Decode-only: this property is read-only, so no encoder is provided.
#[derive(Debug, Clone, PartialEq)]
pub struct CovSubscription {
    pub recipient: RecipientProcess,
    pub monitored_property: ObjectPropertyReference,
    pub issue_confirmed_notifications: bool,
    pub time_remaining: u32,
    pub cov_increment: Option<f32>,
}

impl CovSubscription {
    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let mut pos = 0;

        // recipient [0] BACnetRecipientProcess
        let (recipient_block, consumed) = crate::encoding::extract_context_block(&data[pos..], 0)?;
        pos += consumed;
        let recipient = decode_recipient_process(recipient_block)?;

        // monitoredPropertyReference [1] BACnetObjectPropertyReference
        let (ref_block, consumed) = crate::encoding::extract_context_block(&data[pos..], 1)?;
        pos += consumed;
        let monitored_property = decode_object_property_reference(ref_block)?;

        // issueConfirmedNotifications [2] BOOLEAN
        let (tag, value, consumed) = decode_context_primitive(&data[pos..])?;
        if tag != 2 {
            return Err(EncodingError::InvalidTag);
        }
        let issue_confirmed_notifications = value.first().is_some_and(|&b| b != 0);
        pos += consumed;

        // timeRemaining [3] Unsigned
        let (time_remaining, consumed) = decode_context_unsigned(&data[pos..], 3)?;
        pos += consumed;

        // covIncrement [4] REAL OPTIONAL
        let cov_increment = if pos < data.len() {
            match decode_context_primitive(&data[pos..]) {
                Ok((4, bytes, consumed)) if bytes.len() == 4 => {
                    pos += consumed;
                    Some(f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                }
                _ => None,
            }
        } else {
            None
        };

        Ok((
            Self {
                recipient,
                monitored_property,
                issue_confirmed_notifications,
                time_remaining,
                cov_increment,
            },
            pos,
        ))
    }
}

fn decode_recipient_process(data: &[u8]) -> EncodingResult<RecipientProcess> {
    let (recipient_block, consumed) = crate::encoding::extract_context_block(data, 0)?;
    let (recipient, _) = Recipient::decode(recipient_block)?;
    let (process_identifier, _) = decode_context_unsigned(&data[consumed..], 1)?;
    Ok(RecipientProcess {
        recipient,
        process_identifier,
    })
}

fn decode_object_property_reference(data: &[u8]) -> EncodingResult<ObjectPropertyReference> {
    let mut pos = 0;
    let (object_identifier, consumed) = decode_context_object_id(data, 0)?;
    pos += consumed;
    let (property_identifier, consumed) = decode_context_enumerated(&data[pos..], 1)?;
    pos += consumed;
    let property_array_index = if pos < data.len() {
        match decode_context_unsigned(&data[pos..], 2) {
            Ok((index, _)) => Some(index),
            Err(_) => None,
        }
    } else {
        None
    };
    Ok(ObjectPropertyReference {
        object_identifier,
        property_identifier,
        property_array_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_destination_round_trips() {
        let list = RecipientList {
            destinations: vec![Destination {
                valid_days: vec![true; 7],
                from_time: Time::new(0, 0, 0, 0),
                to_time: Time::new(23, 59, 59, 99),
                recipient: Recipient::Device {
                    device_instance: 5777,
                },
                process_identifier: 777,
                issue_confirmed_notifications: true,
                transitions: vec![true; 3],
            }],
        };
        let mut buf = Vec::new();
        list.encode(&mut buf).unwrap();
        assert_eq!(
            buf,
            vec![
                0x82, 0x01, 0xFE, 0xB4, 0x00, 0x00, 0x00, 0x00, 0xB4, 0x17, 0x3B, 0x3B, 0x63, 0x0C,
                0x02, 0x00, 0x16, 0x91, 0x22, 0x03, 0x09, 0x11, 0x82, 0x05, 0xE0,
            ]
        );
        assert_eq!(RecipientList::decode(&buf).unwrap(), list);
    }

    #[test]
    fn broadcast_address_destination_round_trips() {
        let list = RecipientList {
            destinations: vec![Destination {
                valid_days: vec![false, true, false, true, false, true, false],
                from_time: Time::new(8, 30, 0, 0),
                to_time: Time::new(17, 0, 0, 0),
                recipient: Recipient::Address(BacnetAddress {
                    network_number: 65_535,
                    mac_address: Vec::new(),
                }),
                process_identifier: 1,
                issue_confirmed_notifications: false,
                transitions: vec![true, false, true],
            }],
        };
        let mut buf = Vec::new();
        list.encode(&mut buf).unwrap();
        assert_eq!(
            buf,
            vec![
                0x82, 0x01, 0x54, 0xB4, 0x08, 0x1E, 0x00, 0x00, 0xB4, 0x11, 0x00, 0x00, 0x00, 0x1E,
                0x22, 0xFF, 0xFF, 0x60, 0x1F, 0x21, 0x01, 0x10, 0x82, 0x05, 0xA0,
            ]
        );
        assert_eq!(RecipientList::decode(&buf).unwrap(), list);
    }

    #[test]
    fn address_binding_round_trips() {
        let list = AddressBindingList {
            bindings: vec![AddressBinding {
                device_identifier: ObjectIdentifier::new(DEVICE_OBJECT_TYPE.into(), 12),
                device_address: BacnetAddress {
                    network_number: 0,
                    mac_address: vec![192, 168, 1, 10, 0xBA, 0xC0],
                },
            }],
        };
        let mut buf = Vec::new();
        list.encode(&mut buf).unwrap();
        assert_eq!(AddressBindingList::decode(&buf).unwrap(), list);
    }
}
