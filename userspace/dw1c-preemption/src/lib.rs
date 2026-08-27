#![no_std]
#![forbid(unsafe_code)]

//! Fixed selector-28 actor roles.  The collector binds process identity; these
//! constants only keep the Wyrmroot product construction deterministic.

pub const ACTOR_COUNT: usize = 10;
pub const ROLE_CODES: [u64; ACTOR_COUNT] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
pub const ACTOR_PATHS: [&[u8]; ACTOR_COUNT] = [
    b"test/dw1-c/actor1", b"test/dw1-c/actor2", b"test/dw1-c/actor3", b"test/dw1-c/actor4",
    b"test/dw1-c/actor5", b"test/dw1-c/actor6", b"test/dw1-c/actor7", b"test/dw1-c/actor8",
    b"test/dw1-c/actor9", b"test/dw1-c/actor10",
];

#[must_use]
pub const fn role_for(token: usize) -> Option<u64> {
    if token == 0 || token > ACTOR_COUNT { None } else { Some(ROLE_CODES[token - 1]) }
}
