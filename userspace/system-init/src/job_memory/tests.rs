use super::*;
use deepwyrm_syscall::DwStatus;
use wyrmroot_bootfs::builder::{Builder, FileMode};

extern crate std;
use std::vec::Vec;

const MIB: u64 = (1 << 20) / PAGE_BYTES;
const GIB: u64 = 1024 * MIB;

fn config(cap_mib: u64, reserve_mib: u64) -> PlatformConfig {
    PlatformConfig {
        job_memory_bytes_max: cap_mib << 20,
        resident_reserve_bytes: reserve_mib << 20,
    }
}

#[test]
fn the_budget_is_half_of_free_less_the_reserve() {
    // 2 GiB free: the default reserve is 256 MiB (an eighth), so the jobs
    // share 1792 MiB and each may have half.
    let plan = plan_job_memory(Ok(2 * GIB), Ok(config(0, 0)));
    assert_eq!(plan.reserve_pages, 256 * MIB);
    assert_eq!(u64::from(plan.jobs_limit_pages), 1792 * MIB);
    assert_eq!(u64::from(plan.job_budget_pages), 896 * MIB);
    assert_eq!(plan.source, JobMemorySource::Computed);
    assert_eq!(plan.cause, FallbackCause::None);
    assert_eq!(plan.job_budget_bytes(), 896 << 20);
}

#[test]
fn the_default_reserve_is_the_larger_of_256_mib_and_an_eighth() {
    assert_eq!(
        plan_job_memory(Ok(GIB), Ok(config(0, 0))).reserve_pages,
        256 * MIB
    );
    assert_eq!(
        plan_job_memory(Ok(16 * GIB), Ok(config(0, 0))).reserve_pages,
        2 * GIB
    );
    // A configured reserve replaces the default, smaller or larger.
    let plan = plan_job_memory(Ok(2 * GIB), Ok(config(0, 64)));
    assert_eq!(plan.reserve_pages, 64 * MIB);
    assert_eq!(u64::from(plan.job_budget_pages), (2 * GIB - 64 * MIB) / 2);
}

#[test]
fn the_cap_binds_only_below_half() {
    let capped = plan_job_memory(Ok(2 * GIB), Ok(config(512, 0)));
    assert_eq!(u64::from(capped.job_budget_pages), 512 * MIB);
    assert_eq!(capped.source, JobMemorySource::Capped);
    assert_eq!(capped.cap_pages, 512 * MIB);
    // The jobs group still holds all jobs to free − reserve.
    assert_eq!(u64::from(capped.jobs_limit_pages), 1792 * MIB);
    let loose = plan_job_memory(Ok(2 * GIB), Ok(config(4096, 0)));
    assert_eq!(u64::from(loose.job_budget_pages), 896 * MIB);
    assert_eq!(loose.source, JobMemorySource::Computed);
}

#[test]
fn limits_saturate_below_unlimited() {
    // 64 TiB of free pages is past what a u32 page limit holds.
    let plan = plan_job_memory(Ok(1 << 34), Ok(config(0, 0)));
    assert_eq!(plan.jobs_limit_pages, DW_TASK_GROUP_LIMIT_UNLIMITED - 1);
    assert_eq!(plan.job_budget_pages, DW_TASK_GROUP_LIMIT_UNLIMITED - 1);
    assert_ne!(plan.job_budget_pages, DW_TASK_GROUP_LIMIT_UNLIMITED);
}

#[test]
fn every_failure_falls_back_to_16_mib_never_to_no_cap() {
    let fallback_jobs = FALLBACK_JOB_MEMORY_PAGES * MAX_SHELL_JOBS as u32;
    for (free, config, cause) in [
        (
            Err(FallbackCause::TopicUnreadable),
            Ok(config(512, 0)),
            FallbackCause::TopicUnreadable,
        ),
        (Ok(0), Ok(config(512, 0)), FallbackCause::NoFreeCount),
        (
            Ok(2 * GIB),
            Err(FallbackCause::ConfigMissing),
            FallbackCause::ConfigMissing,
        ),
        (
            Ok(2 * GIB),
            Err(FallbackCause::ConfigMalformed),
            FallbackCause::ConfigMalformed,
        ),
        // Free at or below the reserve, or one page above it.
        (
            Ok(256 * MIB),
            Ok(config(0, 0)),
            FallbackCause::FreeNotAboveReserve,
        ),
        (
            Ok(100 * MIB),
            Ok(config(0, 0)),
            FallbackCause::FreeNotAboveReserve,
        ),
        (
            Ok(256 * MIB + 1),
            Ok(config(0, 0)),
            FallbackCause::FreeNotAboveReserve,
        ),
        (
            Ok(GIB),
            Ok(config(0, 2048)),
            FallbackCause::FreeNotAboveReserve,
        ),
    ] {
        let plan = plan_job_memory(free, config);
        assert_eq!(plan.cause, cause);
        assert_eq!(plan.source, JobMemorySource::Fallback);
        assert_eq!(plan.job_budget_pages, FALLBACK_JOB_MEMORY_PAGES);
        assert_eq!(plan.jobs_limit_pages, fallback_jobs);
    }
    // Two pages above the reserve is the least that budgets a page a job.
    let least = plan_job_memory(Ok(256 * MIB + 2), Ok(config(0, 0)));
    assert_eq!((least.job_budget_pages, least.jobs_limit_pages), (1, 2));
}

fn bootfs(entries: &[(&str, &[u8], FileMode)]) -> Vec<u8> {
    let mut builder = Builder::new();
    builder
        .add(b"system/init", b"init", FileMode::Executable)
        .unwrap();
    for (path, bytes, mode) in entries {
        builder.add(path.as_bytes(), bytes, *mode).unwrap();
    }
    builder.build().unwrap()
}

#[test]
fn the_config_is_read_strictly_from_bootfs() {
    let good = config(512, 0).encode().unwrap();
    assert_eq!(
        read_platform_config(&bootfs(&[(
            PLATFORM_CONFIG_PATH,
            &good,
            FileMode::ReadOnly
        )])),
        Ok(config(512, 0))
    );
    assert_eq!(
        read_platform_config(&bootfs(&[])),
        Err(FallbackCause::ConfigMissing)
    );
    assert_eq!(
        read_platform_config(&bootfs(&[(
            PLATFORM_CONFIG_PATH,
            &good[..32],
            FileMode::ReadOnly
        )])),
        Err(FallbackCause::ConfigMalformed)
    );
    assert_eq!(
        read_platform_config(&bootfs(&[(
            PLATFORM_CONFIG_PATH,
            &good,
            FileMode::Executable
        )])),
        Err(FallbackCause::ConfigMalformed)
    );
    assert_eq!(
        read_platform_config(b"not an archive"),
        Err(FallbackCause::ConfigMalformed)
    );
}

const INIT_GROUP: DwHandle = DwHandle(0x10);
const JOBS_GROUP: DwHandle = DwHandle(0x20);
const FAILURE: NativeError = NativeError::Status(DwStatus(-5));

#[derive(Default)]
struct Groups {
    free_pages: Option<u64>,
    create_fails: bool,
    limit_fails: bool,
    close_fails: bool,
    queried: Vec<DwHandle>,
    created_under: Vec<DwHandle>,
    limits: Vec<(DwHandle, u32, u32)>,
    closed: Vec<DwHandle>,
}

impl JobGroupPlatform for Groups {
    fn query_task_group_memory(
        &mut self,
        group: DwHandle,
    ) -> Result<DwTaskGroupMemoryInfoV1, NativeError> {
        self.queried.push(group);
        self.free_pages
            .map(|free_pages| DwTaskGroupMemoryInfoV1 {
                free_pages,
                ..DwTaskGroupMemoryInfoV1::default()
            })
            .ok_or(FAILURE)
    }
    fn create_task_group(&mut self, parent: DwHandle) -> Result<DwHandle, NativeError> {
        self.created_under.push(parent);
        if self.create_fails {
            Err(FAILURE)
        } else {
            Ok(JOBS_GROUP)
        }
    }
    fn limit_task_group(
        &mut self,
        group: DwHandle,
        class: u32,
        limit: u32,
    ) -> Result<(), NativeError> {
        self.limits.push((group, class, limit));
        if self.limit_fails {
            Err(FAILURE)
        } else {
            Ok(())
        }
    }
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.closed.push(handle);
        if self.close_fails {
            Err(FAILURE)
        } else {
            Ok(())
        }
    }
}

#[test]
fn init_reads_its_own_group_and_limits_a_jobs_group_under_it() {
    let image = bootfs(&[(
        PLATFORM_CONFIG_PATH,
        &config(512, 0).encode().unwrap(),
        FileMode::ReadOnly,
    )]);
    let mut groups = Groups {
        free_pages: Some(2 * GIB),
        ..Groups::default()
    };
    let memory = establish(&mut groups, INIT_GROUP, &image).unwrap();
    assert_eq!(groups.queried, [INIT_GROUP]);
    assert_eq!(groups.created_under, [INIT_GROUP]);
    assert_eq!(
        groups.limits,
        [(
            JOBS_GROUP,
            DW_TASK_GROUP_LIMIT_MEMORY_PAGES,
            (1792 * MIB) as u32
        )]
    );
    assert_eq!(memory.jobs_group, Some(JOBS_GROUP));
    assert_eq!(memory.job_parent(INIT_GROUP), JOBS_GROUP);
    assert_eq!(u64::from(memory.plan.job_budget_pages), 512 * MIB);
    assert!(groups.closed.is_empty());
}

#[test]
fn an_unreadable_topic_still_makes_a_jobs_group_at_the_fallback() {
    let image = bootfs(&[]);
    let mut groups = Groups::default();
    let memory = establish(&mut groups, INIT_GROUP, &image).unwrap();
    assert_eq!(memory.plan.cause, FallbackCause::TopicUnreadable);
    assert_eq!(memory.jobs_group, Some(JOBS_GROUP));
    assert_eq!(
        groups.limits,
        [(
            JOBS_GROUP,
            DW_TASK_GROUP_LIMIT_MEMORY_PAGES,
            FALLBACK_JOB_MEMORY_PAGES * MAX_SHELL_JOBS as u32
        )]
    );
}

#[test]
fn a_jobs_group_that_cannot_be_made_or_limited_leaves_jobs_at_16_mib() {
    let image = bootfs(&[(
        PLATFORM_CONFIG_PATH,
        &config(0, 0).encode().unwrap(),
        FileMode::ReadOnly,
    )]);
    let mut uncreated = Groups {
        free_pages: Some(2 * GIB),
        create_fails: true,
        ..Groups::default()
    };
    let memory = establish(&mut uncreated, INIT_GROUP, &image).unwrap();
    assert_eq!(memory.jobs_group, None);
    assert_eq!(memory.job_parent(INIT_GROUP), INIT_GROUP);
    assert_eq!(memory.plan.cause, FallbackCause::JobsGroup);
    assert_eq!(memory.plan.job_budget_pages, FALLBACK_JOB_MEMORY_PAGES);
    // What was learned before the failure is kept for `status`.
    assert_eq!(memory.plan.free_pages, 2 * GIB);

    let mut unlimited = Groups {
        free_pages: Some(2 * GIB),
        limit_fails: true,
        ..Groups::default()
    };
    let memory = establish(&mut unlimited, INIT_GROUP, &image).unwrap();
    assert_eq!(unlimited.closed, [JOBS_GROUP]);
    assert_eq!(memory.jobs_group, None);
    assert_eq!(memory.plan.cause, FallbackCause::JobsGroup);

    let mut stuck = Groups {
        free_pages: Some(2 * GIB),
        limit_fails: true,
        close_fails: true,
        ..Groups::default()
    };
    assert_eq!(
        establish(&mut stuck, INIT_GROUP, &image),
        Err(InitError::Cleanup)
    );
}

#[test]
fn settling_lasts_while_usage_falls_and_no_longer_than_the_limit() {
    let start = Settle::begin(Some(1000), 0).unwrap();
    // Not yet due: no read.
    assert_eq!(
        start.poll(SETTLE_SAMPLE_NS - 1, || panic!("read early")),
        Some(start)
    );
    // Falling: the pause goes on from the new usage.
    let falling = start.poll(SETTLE_SAMPLE_NS, || Some(900)).unwrap();
    // Level: over.
    assert_eq!(falling.poll(2 * SETTLE_SAMPLE_NS, || Some(900)), None);
    // Rising (a new job started elsewhere): over.
    assert_eq!(falling.poll(2 * SETTLE_SAMPLE_NS, || Some(950)), None);
    // Unreadable: over.
    assert_eq!(falling.poll(2 * SETTLE_SAMPLE_NS, || None), None);
    // Still falling at the limit: over all the same.
    assert_eq!(falling.poll(SETTLE_LIMIT_NS, || Some(1)), None);
    // No usage to start from: no pause.
    assert_eq!(Settle::begin(None, 0), None);
}
