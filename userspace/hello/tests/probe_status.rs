//! The memory probes' failure statuses (Deepwyrm DW2 M8 §13.4 item 2), and
//! the churn probes driven against a recording system.

use std::collections::BTreeSet;

use deepwyrm_syscall::{
    DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND, DW_STATUS_NO_MEMORY, DW_STATUS_NO_RESOURCES,
    DW_STATUS_SUCCESS, DwHandle, DwMemoryObjectCreateFlags, DwStatus,
};
use wyrmroot_hello::probe::{CHURN, churn_commit, churn_create, churn_map};
use wyrmroot_hello::{
    ChurnCalls, MAX_ROUNDS, PROBE_FAILURE_PREFIX, ProbeSite, decode_probe_failure, probe_failure,
    probe_failure_after,
};
use wyrmroot_loader as _;
use wyrmroot_runtime as _;
use wyrmroot_stream_proto as _;

#[test]
fn a_failure_status_round_trips_its_site_and_code() {
    for site in ProbeSite::ALL {
        for status in [DW_STATUS_SUCCESS, DW_STATUS_NO_RESOURCES, DwStatus(-1)] {
            let encoded = probe_failure(site, status);
            assert_eq!(encoded & 0xff00_0000, PROBE_FAILURE_PREFIX);
            let (number, code, round) = decode_probe_failure(encoded).unwrap();
            assert_eq!(number, site as u8, "{site:?}");
            assert_eq!(i32::from(code), -status.0, "{site:?} {status:?}");
            // Every site but the churn probes' says round 0.
            assert_eq!(round, 0, "{site:?}");
            for rounds in [1, 3, 254, 255] {
                let after = probe_failure_after(site, status, rounds);
                assert_eq!(
                    decode_probe_failure(after),
                    Some((number, code, rounds as u8)),
                    "{site:?} {rounds}"
                );
            }
            // More rounds than a status holds saturate.
            for rounds in [256, 300, u32::MAX] {
                let after = probe_failure_after(site, status, rounds);
                assert_eq!(decode_probe_failure(after), Some((number, code, 255)));
            }
        }
    }
    assert_eq!(
        probe_failure(ProbeSite::ChurnCreate, DW_STATUS_NO_RESOURCES),
        0x4D00_260D
    );
    assert_eq!(
        ProbeSite::ChurnCreate.after(DW_STATUS_NO_RESOURCES, 3),
        0x4D03_260D
    );
    assert_eq!(MAX_ROUNDS, 255);
}

#[test]
fn no_resources_is_code_13_and_success_is_never_a_failure() {
    assert_eq!(
        decode_probe_failure(ProbeSite::ChurnCommitCreate.with(DW_STATUS_NO_RESOURCES)),
        Some((39, 13, 0))
    );
    // No kernel status is code 0.
    assert_eq!(ProbeSite::UnknownMode.alone() & 0xff, 0);
    // The probes' own successes and deliberate ends do not decode, and no
    // failure is one of them.
    for status in [0, 1, 2, 0x4800_000d] {
        assert_eq!(decode_probe_failure(status), None);
    }
    for site in ProbeSite::ALL {
        for status in [DW_STATUS_SUCCESS, DW_STATUS_NO_RESOURCES] {
            assert!(probe_failure(site, status) > 2);
        }
    }
}

#[test]
fn every_site_number_is_distinct_and_in_range() {
    let numbers: BTreeSet<u8> = ProbeSite::ALL.iter().map(|site| *site as u8).collect();
    assert_eq!(numbers.len(), ProbeSite::ALL.len());
    assert!(!numbers.contains(&0));
}

/// One recorded kernel call.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Call {
    Create(u64, u32),
    Commit(DwHandle, u64),
    Map(DwHandle, u64),
    Unmap(u64, u64),
    Close(DwHandle),
}

/// A recording system whose creates and maps succeed until a planned
/// refusal.
struct Recorder {
    calls: Vec<Call>,
    creates_left: usize,
    create_refusal: DwStatus,
    maps_left: usize,
    map_refusal: DwStatus,
    next: u64,
}

impl Recorder {
    fn new(creates: usize, create_refusal: DwStatus) -> Self {
        Self {
            calls: Vec::new(),
            creates_left: creates,
            create_refusal,
            maps_left: usize::MAX,
            map_refusal: DW_STATUS_SUCCESS,
            next: 100,
        }
    }
}

impl ChurnCalls for Recorder {
    fn create(
        &mut self,
        size: u64,
        flags: DwMemoryObjectCreateFlags,
    ) -> Result<DwHandle, DwStatus> {
        self.calls.push(Call::Create(size, flags.0));
        if self.creates_left == 0 {
            return Err(self.create_refusal);
        }
        self.creates_left -= 1;
        self.next += 1;
        Ok(DwHandle(self.next))
    }

    fn commit(&mut self, object: DwHandle, size: u64) -> DwStatus {
        self.calls.push(Call::Commit(object, size));
        // A commit stopped at the quota is not a failure of the probe.
        DW_STATUS_NO_RESOURCES
    }

    fn map(&mut self, object: DwHandle, size: u64) -> Result<u64, DwStatus> {
        self.calls.push(Call::Map(object, size));
        if self.maps_left == 0 {
            return Err(self.map_refusal);
        }
        self.maps_left -= 1;
        self.next += 1;
        Ok(self.next << 32)
    }

    fn unmap(&mut self, at: u64, size: u64) -> Result<(), DwStatus> {
        self.calls.push(Call::Unmap(at, size));
        Ok(())
    }

    fn close(&mut self, handle: DwHandle) -> DwStatus {
        self.calls.push(Call::Close(handle));
        DW_STATUS_SUCCESS
    }
}

#[test]
fn a_refused_create_ends_churn_create_with_its_site_and_status() {
    let mut recorder = Recorder::new(3, DW_STATUS_NO_RESOURCES);
    let status = churn_create(&mut recorder);
    // Refused after three completed rounds: round 3.
    assert_eq!(
        status,
        ProbeSite::ChurnCreate.after(DW_STATUS_NO_RESOURCES, 3)
    );
    assert_eq!(decode_probe_failure(status), Some((38, 13, 3)));
    // Three rounds of create and close, then the refused create: nothing
    // else was called.
    let round = |handle| [Call::Create(CHURN, 0), Call::Close(DwHandle(handle))];
    let mut expected: Vec<Call> = [101, 102, 103].into_iter().flat_map(round).collect();
    expected.push(Call::Create(CHURN, 0));
    assert_eq!(recorder.calls, expected);
}

#[test]
fn a_refused_create_ends_churn_commit_with_its_site_and_status() {
    let mut recorder = Recorder::new(2, DW_STATUS_NO_MEMORY);
    let status = churn_commit(&mut recorder);
    assert_eq!(decode_probe_failure(status), Some((39, 12, 2)));
    // A refused commit was not a failure; only the create ended it.
    let on_demand = DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND.0;
    assert_eq!(
        recorder.calls,
        vec![
            Call::Create(CHURN, on_demand),
            Call::Commit(DwHandle(101), CHURN),
            Call::Close(DwHandle(101)),
            Call::Create(CHURN, on_demand),
            Call::Commit(DwHandle(102), CHURN),
            Call::Close(DwHandle(102)),
            Call::Create(CHURN, on_demand),
        ]
    );
}

#[test]
fn churn_map_fails_at_its_create_or_a_first_refused_map() {
    let mut recorder = Recorder::new(0, DW_STATUS_NO_RESOURCES);
    assert_eq!(
        churn_map(&mut recorder),
        ProbeSite::ChurnMapCreate.with(DW_STATUS_NO_RESOURCES)
    );
    // A map refused with mappings kept unmaps them and goes on; one refused
    // with none kept ends the job.
    let mut recorder = Recorder::new(1, DW_STATUS_SUCCESS);
    recorder.maps_left = 2;
    recorder.map_refusal = DW_STATUS_NO_RESOURCES;
    // Two maps succeeded before the refusal that ended it.
    assert_eq!(
        churn_map(&mut recorder),
        ProbeSite::ChurnMapRefused.after(DW_STATUS_NO_RESOURCES, 2)
    );
    let object = DwHandle(101);
    assert_eq!(
        recorder.calls,
        vec![
            Call::Create(CHURN, 0),
            Call::Map(object, CHURN),
            Call::Map(object, CHURN),
            Call::Map(object, CHURN),
            Call::Unmap(102 << 32, CHURN),
            Call::Unmap(103 << 32, CHURN),
            Call::Map(object, CHURN),
        ]
    );
}

#[test]
fn a_create_refused_on_the_first_round_says_round_0() {
    let mut recorder = Recorder::new(0, DW_STATUS_NO_RESOURCES);
    assert_eq!(
        decode_probe_failure(churn_create(&mut recorder)),
        Some((38, 13, 0))
    );
    let mut recorder = Recorder::new(0, DW_STATUS_NO_RESOURCES);
    assert_eq!(
        decode_probe_failure(churn_commit(&mut recorder)),
        Some((39, 13, 0))
    );
    // churn-map's own create says round 0 too.
    let mut recorder = Recorder::new(0, DW_STATUS_NO_RESOURCES);
    assert_eq!(
        decode_probe_failure(churn_map(&mut recorder)),
        Some((34, 13, 0))
    );
}

#[test]
fn three_hundred_rounds_say_255() {
    let mut recorder = Recorder::new(300, DW_STATUS_NO_RESOURCES);
    assert_eq!(
        decode_probe_failure(churn_create(&mut recorder)),
        Some((38, 13, 255))
    );
    let mut recorder = Recorder::new(300, DW_STATUS_NO_RESOURCES);
    assert_eq!(
        decode_probe_failure(churn_commit(&mut recorder)),
        Some((39, 13, 255))
    );
    // 300 maps: 64 kept, the rest unmapped at once, then a refusal unmaps
    // the 64 and the next refusal, with none kept, ends the job.
    let mut recorder = Recorder::new(1, DW_STATUS_SUCCESS);
    recorder.maps_left = 300;
    recorder.map_refusal = DW_STATUS_NO_RESOURCES;
    assert_eq!(
        decode_probe_failure(churn_map(&mut recorder)),
        Some((37, 13, 255))
    );
    let maps = recorder
        .calls
        .iter()
        .filter(|call| matches!(call, Call::Map(..)))
        .count();
    assert_eq!(maps, 302);
}
