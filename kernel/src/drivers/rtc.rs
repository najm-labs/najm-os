//! The CMOS real-time clock: wall-clock time.
//!
//! The kernel has had a *monotonic* clock since the PIT was programmed -
//! ticks since boot, which is what a scheduler needs. It has had no idea
//! what time it is, which is what everything else needs: a filesystem
//! timestamp, a certificate expiry check, a log line a human can correlate
//! with anything.
//!
//! That second one is not decorative. ARCHITECTURE.md section 2e makes
//! Vault Realm eligibility depend on a publisher signature chain, and a
//! signature chain without a clock cannot check whether a certificate has
//! expired or been revoked - so it validates a credential that may have
//! been withdrawn years ago. A trust decision made against an unknown
//! date is not a weaker trust decision; it is a different one.
//!
//! ## The update-in-progress race, and why it needs handling
//!
//! The RTC updates its registers once per second, and reading them
//! *during* that update returns a mixture of old and new values. The
//! classic symptom is reading 00 seconds together with the previous
//! minute - once an hour, on a machine that has been running for a while,
//! with no way to reproduce it. Two defences are used together, which is
//! the standard approach:
//!
//! 1. Wait for the update-in-progress flag (status register A, bit 7) to
//!    clear before reading.
//! 2. Read the whole time twice and require the two to agree. The flag
//!    can be set immediately after being checked, so waiting for it is
//!    necessary and not sufficient.
//!
//! ## No timezone, and no attempt to guess one
//!
//! The RTC may be running in UTC or in local time, and there is no way to
//! tell from the hardware - the convention is an agreement between the
//! operating systems installed on the machine. This module reports
//! exactly what the hardware says and calls it what it is. Guessing an
//! offset would produce a timestamp that is confidently wrong, which is
//! worse than one that is honestly unqualified.

use crate::serial_println;
use x86_64::instructions::port::Port;

const CMOS_ADDRESS: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

const REG_SECONDS: u8 = 0x00;
const REG_MINUTES: u8 = 0x02;
const REG_HOURS: u8 = 0x04;
const REG_DAY: u8 = 0x07;
const REG_MONTH: u8 = 0x08;
const REG_YEAR: u8 = 0x09;
const REG_STATUS_A: u8 = 0x0A;
const REG_STATUS_B: u8 = 0x0B;

/// Wall-clock time as the RTC reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DateTime {
    /// Full year, e.g. 2026. The hardware stores two digits; see
    /// `read_raw` for how the century is recovered.
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl DateTime {
    /// Whether this looks like a real date.
    ///
    /// The RTC is a battery-backed chip that can hold garbage - a dead
    /// battery, a virtual machine that never set it, a first boot. Code
    /// that treats whatever it returns as authoritative will happily
    /// decide the year is 2165 and that every certificate has expired.
    /// Range-checking is cheap and turns that into a detectable
    /// condition.
    pub fn is_plausible(&self) -> bool {
        self.year >= 2000
            && self.year <= 2199
            && (1..=12).contains(&self.month)
            && (1..=31).contains(&self.day)
            && self.hour < 24
            && self.minute < 60
            // 60 is legal: it is a leap second.
            && self.second <= 60
    }

    /// Seconds since the Unix epoch.
    ///
    /// Computed with the civil-from-days algorithm rather than a table of
    /// month lengths plus leap-year special cases, because the table
    /// version is where off-by-one errors live - specifically around
    /// February in century years, which are only wrong once every hundred
    /// years and therefore never caught.
    pub fn to_unix_seconds(&self) -> u64 {
        let year = self.year as i64;
        let month = self.month as i64;
        let day = self.day as i64;

        // Shift the year so that March is month 1 - this is the trick
        // that makes the leap day the *last* day of the year, so it needs
        // no special case at all.
        let year = if month <= 2 { year - 1 } else { year };
        let era = if year >= 0 { year } else { year - 399 } / 400;
        let year_of_era = year - era * 400;
        let month_shifted = if month > 2 { month - 3 } else { month + 9 };
        let day_of_year = (153 * month_shifted + 2) / 5 + day - 1;
        let day_of_era =
            year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days_since_epoch = era * 146_097 + day_of_era - 719_468;

        (days_since_epoch * 86_400
            + self.hour as i64 * 3_600
            + self.minute as i64 * 60
            + self.second as i64)
            .max(0) as u64
    }
}

fn read_register(register: u8) -> u8 {
    // Safety: 0x70/0x71 are the fixed CMOS index and data ports. Bit 7 of
    // the index port is the NMI-disable flag; it is left clear, so this
    // does not change the machine's NMI state as a side effect - a real
    // hazard, since a driver that disables NMIs and forgets to restore
    // them masks the one interrupt that reports hardware faults.
    unsafe {
        let mut address: Port<u8> = Port::new(CMOS_ADDRESS);
        let mut data: Port<u8> = Port::new(CMOS_DATA);
        address.write(register & 0x7F);
        data.read()
    }
}

fn update_in_progress() -> bool {
    read_register(REG_STATUS_A) & 0x80 != 0
}

/// Binary-coded decimal to binary.
///
/// The RTC may report either encoding, and which one is a configuration
/// bit rather than a constant - so this is applied conditionally, based
/// on what status register B actually says.
fn from_bcd(value: u8) -> u8 {
    (value & 0x0F) + ((value >> 4) * 10)
}

fn read_raw() -> DateTime {
    while update_in_progress() {
        core::hint::spin_loop();
    }

    let second = read_register(REG_SECONDS);
    let minute = read_register(REG_MINUTES);
    let hour = read_register(REG_HOURS);
    let day = read_register(REG_DAY);
    let month = read_register(REG_MONTH);
    let year = read_register(REG_YEAR);
    let status_b = read_register(REG_STATUS_B);

    let binary_mode = status_b & 0x04 != 0;
    let twenty_four_hour = status_b & 0x02 != 0;

    let convert = |value: u8| if binary_mode { value } else { from_bcd(value) };

    // The hour register's high bit is the PM flag in 12-hour mode, and
    // it survives the BCD conversion - so it has to be masked off before
    // converting and re-applied after, not the other way round.
    let pm = !twenty_four_hour && (hour & 0x80) != 0;
    let mut hour = convert(hour & 0x7F);
    if pm && hour != 12 {
        hour += 12;
    } else if !twenty_four_hour && !pm && hour == 12 {
        // 12 AM is hour 0. Without this, midnight reads as noon.
        hour = 0;
    }

    // The century register (0x32) exists but is not reliably present, so
    // the century is inferred instead. Two digits below 70 mean the 21st
    // century - the same windowing every BIOS-era system uses. This
    // breaks in 2070, which is recorded here rather than left as a
    // surprise for whoever is maintaining it then.
    let year = convert(year) as u16;
    let year = if year < 70 { 2000 + year } else { 1900 + year };

    DateTime {
        year,
        month: convert(month),
        day: convert(day),
        hour,
        minute: convert(minute),
        second: convert(second),
    }
}

/// Reads the wall clock, retrying until two consecutive reads agree.
///
/// The retry is the second half of the update-race defence described in
/// the module docs: the update-in-progress flag can be set immediately
/// after being checked, so waiting for it is necessary and not
/// sufficient. Two identical reads separated by the read itself cannot
/// both have straddled the same one-second update.
pub fn now() -> DateTime {
    let mut previous = read_raw();
    // Bounded rather than a bare loop. If the RTC is broken or absent -
    // an emulator with no CMOS, a dead battery mid-update - an unbounded
    // retry would hang the boot, and hanging while reading a *clock* is
    // an unusually confusing way for a machine to fail.
    for _ in 0..10 {
        let current = read_raw();
        if current == previous {
            return current;
        }
        previous = current;
    }
    previous
}

/// Reads the clock and reports it. Returns `None` if what the hardware
/// said cannot be a real date - see `DateTime::is_plausible`.
pub fn init() -> Option<DateTime> {
    let now = now();

    if !now.is_plausible() {
        serial_println!(
            "Najm Kernel: the RTC reported {:04}-{:02}-{:02} {:02}:{:02}:{:02}, which is not a \
             plausible date - treating wall-clock time as unavailable rather than trusting it",
            now.year,
            now.month,
            now.day,
            now.hour,
            now.minute,
            now.second
        );
        return None;
    }

    serial_println!(
        "Najm Kernel: wall clock is {:04}-{:02}-{:02} {:02}:{:02}:{:02} ({} seconds since the \
         Unix epoch, timezone unknown - the RTC does not say whether it runs in UTC or local time)",
        now.year,
        now.month,
        now.day,
        now.hour,
        now.minute,
        now.second,
        now.to_unix_seconds()
    );

    Some(now)
}
