//! Typed BACnet constructed datatypes with symmetric wire encode/decode.
//!
//! These are the structured property values that appear inside services and
//! object properties — schedules, calendars, recipient lists — modelled as
//! Rust types rather than raw byte buffers. Embedded primitive values use
//! [`crate::property::PropertyValue`] as the neutral value type.

pub mod calendar;
pub mod datetime;
pub mod recipient;
pub mod schedule;

pub use calendar::{CalendarEntry, DateList, WeekNDay};
pub use datetime::{Date, Time};
pub use recipient::{
    AddressBinding, AddressBindingList, BacnetAddress, CovSubscription, Destination,
    ObjectPropertyReference, Recipient, RecipientList, RecipientProcess,
};
pub use schedule::{
    DailySchedule, ExceptionSchedule, SpecialEvent, SpecialEventPeriod, TimeValue, WeeklySchedule,
};
