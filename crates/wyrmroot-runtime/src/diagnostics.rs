//! Development-only diagnostics boundary.
//!
//! No production console, stdio, TTY, or logging ABI is defined by WYR0-D1. The future exact
//! syscall binding may add test-only diagnostic plumbing without making guest correctness depend
//! on it.
