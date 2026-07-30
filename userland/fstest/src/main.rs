//! A userland program that exercises the Najm OS filesystem interface.
//!
//! Its whole reason to exist is to be a *second, different* binary. As
//! long as there was one program and it was the ramdisk, "the loader can
//! run a program" and "the loader can run the one thing the ramdisk
//! contains" were the same statement, and no test could tell them apart.
//! This one is loaded by path (`/bin/fstest`) out of a namespace that
//! contains other things, which makes the filesystem load-bearing rather
//! than decorative.
//!
//! Every check below reports `good:` or `BAD:`. The boot-test harness
//! greps for `BAD:` and fails the run, so these are real assertions, not
//! log decoration - and each negative test checks the *specific* error
//! number, because "the kernel refused" and "the kernel refused for the
//! reason I was testing" are different claims.

#![no_std]
#![no_main]

use najm_abi::{open_flags, seek, FileInfo};
use najm_std as sys;

/// The exit status this program uses when every check passed. Distinct
/// from `hello`'s 7 so the kernel's report identifies *which* program
/// finished, not merely that something did.
const SUCCESS: u32 = 11;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let _ = sys::write(b"[fstest] a second, different binary is running - loaded by path\n");

    let _ = sys::write(b"[fstest] pid is ");
    sys::write_u64(sys::getpid());
    let _ = sys::write(b"\n");

    check_stat();
    check_read();
    check_seek();
    check_readdir();
    check_refusals();
    check_ipc();

    sys::exit(SUCCESS);
}

/// `stat` must report a real size for a real file, and refuse a path that
/// does not exist.
fn check_stat() {
    let mut info = FileInfo::default();
    match sys::stat(b"/etc/motd", &mut info) {
        Ok(_) if info.size > 0 && info.is_directory == 0 => {
            let _ = sys::write(b"[fstest] good: stat('/etc/motd') reports a file of ");
            sys::write_u64(info.size);
            let _ = sys::write(b" bytes\n");
        }
        Ok(_) => {
            let _ = sys::write(b"[fstest] BAD: stat('/etc/motd') reported an empty file or a directory\n");
        }
        Err(_) => {
            let _ = sys::write(b"[fstest] BAD: stat('/etc/motd') failed\n");
        }
    }

    let mut dir_info = FileInfo::default();
    match sys::stat(b"/etc", &mut dir_info) {
        Ok(_) if dir_info.is_directory != 0 => {
            let _ = sys::write(b"[fstest] good: stat('/etc') reports a directory\n");
        }
        _ => {
            let _ = sys::write(b"[fstest] BAD: stat('/etc') did not report a directory\n");
        }
    }
}

/// Reading a file must return its actual contents, and reading past the
/// end must return zero rather than repeating or faulting.
fn check_read() {
    let Ok(descriptor) = sys::open(b"/etc/motd", open_flags::READ) else {
        let _ = sys::write(b"[fstest] BAD: could not open /etc/motd\n");
        return;
    };

    let mut buffer = [0u8; 128];
    let Ok(read) = sys::read(descriptor, &mut buffer) else {
        let _ = sys::write(b"[fstest] BAD: read of /etc/motd failed\n");
        return;
    };

    if read == 0 {
        let _ = sys::write(b"[fstest] BAD: read of /etc/motd returned no bytes\n");
        return;
    }

    // Echo the contents back, which is the actual proof: these bytes were
    // put in the archive by the build script and have travelled through
    // the boot image, the mount, the descriptor table and two address
    // spaces to get here.
    let _ = sys::write(b"[fstest] good: /etc/motd contains: ");
    let _ = sys::write(&buffer[..read as usize]);

    // A second read from the same descriptor must return 0 - the cursor
    // is at the end. A descriptor whose position never advanced would
    // return the same bytes forever, which is a bug that looks exactly
    // like success on the first read.
    match sys::read(descriptor, &mut buffer) {
        Ok(0) => {
            let _ = sys::write(b"[fstest] good: a second read returned 0 - the cursor advanced\n");
        }
        _ => {
            let _ = sys::write(b"[fstest] BAD: the read cursor did not advance\n");
        }
    }

    let _ = sys::close(descriptor);

    // Closing twice must fail. In a system that reuses descriptor
    // numbers, a double close that silently succeeds is the bug that
    // eventually closes some other part of the program's file.
    match sys::close(descriptor) {
        Err(_) => {
            let _ = sys::write(b"[fstest] good: closing an already-closed descriptor was refused\n");
        }
        Ok(_) => {
            let _ = sys::write(b"[fstest] BAD: a double close succeeded\n");
        }
    }
}

/// Seeking must reposition the cursor, and must clamp rather than run off
/// the end.
fn check_seek() {
    let Ok(descriptor) = sys::open(b"/etc/motd", open_flags::READ) else {
        let _ = sys::write(b"[fstest] BAD: could not open /etc/motd for seeking\n");
        return;
    };

    let mut first = [0u8; 8];
    let first_read = sys::read(descriptor, &mut first).unwrap_or(0);

    // Checked explicitly, because without it this whole test passes
    // vacuously: two reads that both return nothing leave two identical
    // buffers of zeroes, and comparing them proves that seeking works
    // exactly as well as it proves that reading is broken. That is not a
    // hypothetical - it is what this test did before descriptor
    // allocation was fixed, and it reported success the entire time.
    if first_read != first.len() as u64 {
        let _ = sys::write(b"[fstest] BAD: the initial read for the seek test returned nothing\n");
        let _ = sys::close(descriptor);
        return;
    }

    // Back to the start, then read again: the same bytes must come back.
    // This is what distinguishes a cursor that moved from one that was
    // never consulted.
    match sys::seek(descriptor, 0, seek::SET) {
        Ok(0) => {}
        _ => {
            let _ = sys::write(b"[fstest] BAD: seek to the start did not return position 0\n");
            let _ = sys::close(descriptor);
            return;
        }
    }

    let mut again = [0u8; 8];
    let again_read = sys::read(descriptor, &mut again).unwrap_or(0);

    if first == again && again_read == first_read {
        let _ = sys::write(b"[fstest] good: seeking back to 0 re-read the same bytes\n");
    } else {
        let _ = sys::write(b"[fstest] BAD: seeking back to 0 returned different bytes\n");
    }

    // Seeking far past the end must clamp to the file size, not report a
    // position that does not exist. An unclamped position would make the
    // next read return 0 for a reason the caller cannot distinguish from
    // a genuine end of file.
    let mut info = FileInfo::default();
    let _ = sys::stat(b"/etc/motd", &mut info);
    match sys::seek(descriptor, 1_000_000, seek::SET) {
        Ok(position) if position == info.size => {
            let _ = sys::write(b"[fstest] good: seeking past the end clamped to the file size\n");
        }
        _ => {
            let _ = sys::write(b"[fstest] BAD: seeking past the end was not clamped\n");
        }
    }

    let _ = sys::close(descriptor);
}

/// Listing a directory must return more than one entry, and must not
/// recurse.
fn check_readdir() {
    let Ok(descriptor) = sys::open(b"/etc", open_flags::DIRECTORY) else {
        let _ = sys::write(b"[fstest] BAD: could not open /etc as a directory\n");
        return;
    };

    let mut buffer = [0u8; 256];
    let Ok(written) = sys::readdir(descriptor, &mut buffer) else {
        let _ = sys::write(b"[fstest] BAD: readdir('/etc') failed\n");
        return;
    };

    // Entries come back NUL-separated. Counting terminators rather than
    // parsing names, because the count is the property under test: one
    // entry would be indistinguishable from a readdir that returns
    // whatever it found first.
    let entries = buffer[..written as usize].iter().filter(|&&b| b == 0).count();

    if entries >= 2 {
        let _ = sys::write(b"[fstest] good: readdir('/etc') listed ");
        sys::write_u64(entries as u64);
        let _ = sys::write(b" entries:");
        for name in buffer[..written as usize].split(|&b| b == 0) {
            if name.is_empty() {
                continue;
            }
            let _ = sys::write(b" ");
            let _ = sys::write(name);
        }
        let _ = sys::write(b"\n");
    } else {
        let _ = sys::write(b"[fstest] BAD: readdir('/etc') listed fewer than two entries\n");
    }

    let _ = sys::close(descriptor);
}

/// The negative half: things the kernel must refuse, each checked for the
/// specific reason it should be refused for.
fn check_refusals() {
    // A path that does not exist.
    match sys::open(b"/nonexistent", open_flags::READ) {
        Err(e) if sys::is_enoent(e) => {
            let _ = sys::write(b"[fstest] good: opening a missing path gave ENOENT\n");
        }
        _ => {
            let _ = sys::write(b"[fstest] BAD: opening a missing path was not refused with ENOENT\n");
        }
    }

    // Path traversal. This is the check that matters most in this whole
    // file: an archive-backed filesystem that resolves `..` is one where
    // a program can name anything the kernel can, and the failure is
    // silent because the path *looks* like it addresses something inside
    // the namespace.
    match sys::open(b"/etc/../etc/motd", open_flags::READ) {
        Err(e) if sys::is_einval(e) => {
            let _ = sys::write(b"[fstest] good: a path containing '..' was rejected outright\n");
        }
        _ => {
            let _ = sys::write(b"[fstest] BAD: a path containing '..' was not rejected\n");
        }
    }

    // A relative path has no meaning without a working directory, which
    // this system does not have.
    match sys::open(b"etc/motd", open_flags::READ) {
        Err(e) if sys::is_einval(e) => {
            let _ = sys::write(b"[fstest] good: a relative path was rejected\n");
        }
        _ => {
            let _ = sys::write(b"[fstest] BAD: a relative path was not rejected\n");
        }
    }

    // The filesystem is read-only, and says so rather than opening
    // read-only and letting the program discover it later.
    match sys::open(b"/etc/motd", open_flags::WRITE) {
        Err(e) if sys::is_enotsup(e) => {
            let _ = sys::write(b"[fstest] good: opening for write was refused with ENOTSUP\n");
        }
        _ => {
            let _ = sys::write(b"[fstest] BAD: opening for write was not refused\n");
        }
    }

    // Reading a directory as a byte stream would expose the archive's
    // internal representation as if it were file content.
    if let Ok(descriptor) = sys::open(b"/etc", open_flags::DIRECTORY) {
        let mut buffer = [0u8; 16];
        match sys::read(descriptor, &mut buffer) {
            Err(e) if sys::is_enotsup(e) => {
                let _ = sys::write(b"[fstest] good: reading a directory as a file was refused\n");
            }
            _ => {
                let _ = sys::write(b"[fstest] BAD: reading a directory as a file was allowed\n");
            }
        }
        let _ = sys::close(descriptor);
    }

    // A buffer pointer the kernel must refuse. The destination is the
    // kernel's own heap, which is mapped and present - so the only thing
    // that can reject it is the user/supervisor check, which is exactly
    // the property under test.
    if let Ok(descriptor) = sys::open(b"/etc/motd", open_flags::READ) {
        // Safety: none is claimed. The kernel validates every user
        // pointer against the calling process's page tables before
        // writing through it; this is safe to *call* precisely because
        // the kernel does not trust it.
        let buffer = unsafe {
            core::slice::from_raw_parts_mut(
                najm_abi::layout::KERNEL_PROBE_ADDRESS as *mut u8,
                16,
            )
        };
        match sys::read(descriptor, buffer) {
            Err(e) if sys::is_efault(e) => {
                let _ = sys::write(
                    b"[fstest] good: the kernel refused to write file data into its own heap\n",
                );
            }
            _ => {
                let _ = sys::write(b"[fstest] BAD: the kernel wrote into a kernel address\n");
            }
        }
        let _ = sys::close(descriptor);
    }
}

/// Ports: the round trip, and the refusals.
///
/// This process is in the Home Realm, which holds both IPC rights - a
/// Home application offering a service to other applications is ordinary.
/// A Gaming Realm process holds neither, which is what makes the
/// capability check here more than decoration.
fn check_ipc() {
    const NAME: &[u8] = b"os.najm.fstest";

    let Ok(port) = sys::port_create(NAME) else {
        let _ = sys::write(b"[fstest] BAD: port_create failed\n");
        return;
    };

    // Claiming the same name twice must fail. Without this check, a
    // second process could register a name a service already holds and
    // receive messages meant for it - which is the whole reason creating
    // a port is a stronger right than connecting to one.
    match sys::port_create(NAME) {
        Err(e) if sys::is_eexist(e) => {
            let _ = sys::write(b"[fstest] good: claiming a port name twice was refused\n");
        }
        _ => {
            let _ = sys::write(b"[fstest] BAD: a port name was claimed twice\n");
        }
    }

    // Receiving from an empty queue must return EAGAIN, not block and not
    // succeed with zero bytes. A zero-length success is indistinguishable
    // from an empty message, which is a real thing to send.
    let mut buffer = [0u8; 64];
    match sys::port_recv(port, &mut buffer) {
        Err(e) if sys::is_eagain(e) => {
            let _ = sys::write(b"[fstest] good: receiving from an empty port gave EAGAIN\n");
        }
        _ => {
            let _ = sys::write(b"[fstest] BAD: an empty port did not report EAGAIN\n");
        }
    }

    // The round trip. Connecting by name must find the port this process
    // just created, and the bytes must arrive unchanged.
    let Ok(connected) = sys::port_connect(NAME) else {
        let _ = sys::write(b"[fstest] BAD: port_connect could not find the port\n");
        return;
    };

    const MESSAGE: &[u8] = b"ping";
    if sys::port_send(connected, MESSAGE).is_err() {
        let _ = sys::write(b"[fstest] BAD: port_send failed\n");
        return;
    }

    match sys::port_recv(port, &mut buffer) {
        Ok(received) if &buffer[..received as usize] == MESSAGE => {
            let _ = sys::write(b"[fstest] good: a message survived the round trip intact: ");
            let _ = sys::write(&buffer[..received as usize]);
            let _ = sys::write(b"\n");
        }
        _ => {
            let _ = sys::write(b"[fstest] BAD: the message did not survive the round trip\n");
        }
    }

    // Connecting to a name nobody registered must fail, rather than
    // creating one implicitly - which would let a typo silently produce a
    // port that no service is listening on.
    match sys::port_connect(b"os.najm.nonexistent") {
        Err(e) if sys::is_enoent(e) => {
            let _ = sys::write(b"[fstest] good: connecting to an unregistered name gave ENOENT\n");
        }
        _ => {
            let _ = sys::write(b"[fstest] BAD: connecting to an unregistered name succeeded\n");
        }
    }

    // A message larger than the kernel's limit must be refused before it
    // is copied - the allocation is the cost, not the queueing.
    let oversized = [0u8; 8192];
    match sys::port_send(connected, &oversized) {
        Err(e) if sys::is_einval(e) => {
            let _ = sys::write(b"[fstest] good: an oversized message was refused\n");
        }
        _ => {
            let _ = sys::write(b"[fstest] BAD: an oversized message was accepted\n");
        }
    }

    let _ = sys::port_close(port);
}

/// Required by `#![no_std]`.
///
/// Deliberately does not format `_info`: `core::fmt` on a fixed stack
/// with no allocator is a real risk of faulting *inside* the panic
/// handler, which would replace a clear message with a confusing one.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    let _ = sys::write(b"[fstest] PANIC\n");
    sys::exit(101);
}
