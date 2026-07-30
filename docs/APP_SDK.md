# Building apps for Najm OS

## The problem this document answers

> *"For installing apps it's from a store like the App Store on Mac, but
> called Najm Store — and I don't know how to program a language like
> Swift to make programs. Find smart solutions."*

That is two problems wearing one coat, and separating them is most of the
answer:

1. **Nobody will write apps for a new OS.** Every operating system that
   has ever launched has faced this, and almost all of them lost. An app
   store with nothing in it is worse than no app store, because it makes
   the emptiness official.
2. **The person building the OS should not be blocked on learning a new
   language to make it useful.**

The second is the easier one and the answer is not "invent a language."
Inventing a language is how projects spend three years building a
compiler nobody asked for. The answer is that **most applications are not
programs in an interesting sense** — they are a description of a screen,
a list of things that happen when you touch it, and some data. Swift is
not what makes an iPhone app; SwiftUI's declarative layer is, and that
layer is a data format with a renderer behind it.

So Najm OS has four ways to make an application, and only the last one is
systems programming.

---

## Tier 0: Bring the software that already exists — Mirage

**Status: the loader and thunk architecture work; the API surface is four
functions.**

The fastest path to a useful catalogue is not writing new applications,
it is running existing ones. This is exactly the bet Valve made with
Proton, and it worked: the Steam Deck shipped with a Linux kernel and a
catalogue of Windows games, and most users never knew.

`kernel/src/mirage/` is that architecture. A Windows PE32+ binary loads,
relocates, has its imports bound to generated ABI-translation thunks, and
runs at Ring 3 with the same isolation a native process gets. What is
missing is not the mechanism but the API surface — four Win32 functions
against Wine's tens of thousands.

The honest framing, which matters more than the optimistic one: **this is
the hardest of the four tiers and the one most likely to consume years.**
Wine has been at it since 1993. What Najm OS has is the part that would
otherwise have to be invented; what it does not have is the part that is
mostly unglamorous, endless, and unavoidable. See `kernel/src/mirage.rs`
for exactly where the line is.

---

## Tier 1: Declarative apps — no code at all

**Status: the manifest format is implemented and parsed
(`kernel/src/store.rs`). The UI markup is specified below and not yet
implemented.**

An enormous fraction of real applications are: some screens, some
controls, some data, and a few rules about what happens when you press
things. Writing that as imperative code is a choice, not a requirement.

A Najm app in this tier is two text files and some assets. Here is a
complete one:

```ini
# app.najm — the manifest. Already parsed by kernel/src/store.rs.
id        = os.najm.notes
name      = Notes
version   = 1.0.0
publisher = Najm Labs
entry     = ui/main.nml

# A *request*. The Store decides what is granted; see below.
realm = home

capability = file_read
capability = file_write
capability = surface_create
```

```xml
<!-- ui/main.nml — the interface. Specification below; not yet implemented. -->
<screen title="Notes" theme="follow-system">
  <column padding="16" gap="12">
    <text style="heading">My notes</text>

    <list source="notes.json" empty="Nothing here yet.">
      <row>
        <text bind="title" style="body"/>
        <text bind="modified" style="caption"/>
      </row>
    </list>

    <field id="draft" placeholder="Write something..." multiline="true"/>

    <button label="Save" on:press="notes.append(draft); draft.clear()"/>
  </column>
</screen>
```

There is no build step, no compiler, and no language to learn beyond the
markup itself. The `on:press` attribute is deliberately a *tiny*
expression language — property access and method calls on declared
objects — not a general-purpose one. That restriction is the feature: an
app that cannot express arbitrary computation cannot express arbitrary
malice, and the renderer can reason about what an app will do before
running it.

### Why this is safe in a way a scripting language is not

The renderer is a userland process in the app's own Realm. It parses the
markup with the same discipline the kernel applies to every other
untrusted input (see `kernel/src/fs.rs` and `abi/src/archive.rs`): bounds
checked, rejected rather than repaired, no includes, no references that
point outside the document.

An app in this tier **cannot make a syscall**. It cannot open a file the
manifest did not declare, cannot reach the network, cannot spawn
anything. Its entire capability set is what the `<list source="...">`
elements name, and the Store can show a user that complete list before
installation — because it *is* complete, not a summary of one.

### What this tier cannot do

Games, anything with custom rendering, anything computationally
interesting, anything needing a background thread. Those are Tier 3, and
that is fine: they are also the applications whose authors are least
likely to be blocked by needing a compiler.

---

## Tier 2: Scripted apps — logic without systems programming

**Status: not implemented. Design recorded so Tier 1's expression
language is not accidentally grown into this by degrees.**

Between "a form" and "a program" there is a large middle: apps that need
loops, arithmetic, and their own data structures, but not threads, not
raw memory, and not performance.

The intended answer is **WebAssembly**, and the reasoning is worth
stating because "add a scripting language" usually means inventing one:

- It is a **specified, stable bytecode** with multiple independent
  implementations, so Najm OS would be implementing something rather than
  designing it.
- It is **sandboxed by construction.** A WASM module has linear memory
  and imported functions and no other way to affect anything. That maps
  exactly onto the capability model: the imports a module is given *are*
  its capability set, enforced by the runtime rather than checked by it.
- **Every language already targets it.** Rust, C, Go, C#, Python
  (via Pyodide), AssemblyScript. "Which language do I write Najm apps in"
  becomes "whichever one you already know," which is the correct answer to
  a question that should never have been asked.

A WASM interpreter is a few thousand lines; a baseline JIT is more, and
would need the W^X map-twice-and-flip dance the ABI already describes
(`abi/src/lib.rs`, `map_flags::EXEC`).

---

## Tier 3: Native apps — the full interface

**Status: working. Three programs in `userland/` use it.**

A native app is a `no_std` Rust program linked against `najm-std`
(`userland/najm-std/`), which wraps the syscall interface. `userland/gui/`
is a complete worked example: it asks which Realm it is in, gets a
surface, draws a frame, and handles the compositor refusing a malformed
one.

This tier gets everything: surfaces, input, files, the clock, and
whatever the Realm's capability set allows. It is also the only tier
where a mistake can be a memory-safety bug rather than a validation
error, which is why it is the last one listed rather than the first.

---

## How the Store fits

The Store is not a separate trust system bolted on afterwards. It is the
enforcement point for ARCHITECTURE.md section 2e, and the rule is one
sentence:

> **A package's manifest states what it wants. It never states what it
> gets.**

Implemented today in `kernel/src/store.rs`:

| Step | What happens |
|---|---|
| Integrity | SHA-256 over manifest and payload together. One flipped byte and the package is refused. |
| Signature | **Not implemented — fails closed.** No package can currently be elevated above Home. |
| Realm | Computed from the signature status. The manifest's request is compared against the result, never fed into it. |
| Capabilities | The manifest's requests are *intersected* with what the granted Realm provides. A manifest cannot acquire a right by listing it. |

That last row is the one people get wrong. A manifest requesting
`exclusive_scanout` in a Home Realm package does not receive it — the
request can only ever narrow. This makes the manifest genuinely useful
for the thing it should be useful for (an app declaring it needs *less*
than it could have, which a user can see and trust) and useless for the
thing it must not be.

### Why the signature check failing closed matters

It would have been easy to write a verifier that returns `true` with a
`// TODO` above it, and the system would work perfectly today. It fails
closed instead, so nothing can be elevated at all, and a self-test asserts
that — a package that asked for Vault and received it fails the boot.

An unfinished trust check has two possible failure directions, and only
one of them is safe to leave in a repository.

---

## Bootstrapping a catalogue: the ordering that actually works

Purely as a plan, since the technical work above does not answer the
harder question:

1. **Tier 0 first.** A new OS with no software is a demo. Mirage is the
   only tier that can produce a catalogue without anyone writing anything
   new, which is why it is worth the years it will take.
2. **Tier 1 for the long tail.** The applications that never get ported
   are small ones whose authors will not learn a new SDK. Removing the
   SDK entirely is the only thing that reaches them.
3. **Tier 2 when someone asks.** Not before. A scripting runtime built
   before there is a program that needs it will be shaped by guesses.
4. **Tier 3 is already there** for the people who would have built on the
   raw interface anyway, and it is what the other tiers are implemented
   in.

---

## What is honestly missing

Listed here rather than at the end of a feature list, because the gap
between "specified" and "implemented" is where this kind of document
usually misleads:

- **The `.nml` renderer.** Tier 1's markup is a specification in this
  file and nothing else. The manifest half is real and parsed; the UI half
  is not.
- **The Store's user interface.** There is no browsing, no installing, no
  updating. `store::scan` verifies packages found in `/apps` and reports
  what they would be granted. The policy is the hard part and it is done;
  the front end is not.
- **Ed25519 signature verification**, without which no package can ever
  be elevated. See `kernel/src/store.rs`.
- **A WASM runtime**, for Tier 2.
- **Persistence.** The filesystem is read-only and lives in the boot
  image, so nothing an app writes survives a reboot — because there is
  nowhere to write it. This blocks every tier equally and is the single
  most useful thing to build next.
