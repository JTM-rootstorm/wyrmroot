//! Each job's memory budget and the jobs group (DW2 §10.1, §10.3 item 7).
//!
//! Once per boot, after the resident roles have started and before the
//! first job, init reads the memory topic on its root TaskGroup and the
//! product's platform configuration, and plans:
//!
//! - a reserve kept back for the residents: the config's
//!   `resident_reserve_bytes`, or by default the larger of 256 MiB and one
//!   eighth of free;
//! - a jobs TaskGroup under init's own whose MEMORY_PAGES limit is
//!   free − reserve, so all jobs together can never take the reserve;
//! - each job's budget, `min((free − reserve) / 2, cap)`, its own group's
//!   MEMORY_PAGES limit.
//!
//! A limit's largest value means unlimited, so both are saturated one below
//! it. Failure is never "no cap": if the topic cannot be read, the config
//! is missing or malformed, free is not above the reserve, or the jobs group
//! cannot be made, the plan records why and every job gets the old 16 MiB,
//! with the jobs group (when it exists) held to what the old jobs could
//! reach together. Init has no log stream; the plan, its cause included,
//! is what the shell's `memory` command reports (WRLJ MEMORY).

use deepwyrm_syscall::{
    DW_TASK_GROUP_LIMIT_MEMORY_PAGES, DW_TASK_GROUP_LIMIT_UNLIMITED, DwHandle,
    DwTaskGroupMemoryInfoV1,
};
use wyrmroot_bootfs::{
    archive::Archive,
    platform_config::{PLATFORM_CONFIG_PATH, PlatformConfig},
};

use wyrmroot_launch_proto::MemoryReport;
use wyrmroot_runtime::NativeError;

use crate::{InitError, InitPlatform, jobs::MAX_SHELL_JOBS};

pub(crate) const PAGE_BYTES: u64 = 4096;
/// The budget every job had before DW2 M5, and still gets when the plan
/// cannot be computed: 16 MiB.
pub const FALLBACK_JOB_MEMORY_PAGES: u32 = 4096;
/// The default reserve's floor: 256 MiB.
pub const DEFAULT_RESERVE_FLOOR_PAGES: u64 = (256 << 20) / PAGE_BYTES;
/// The largest finite limit; the next value up means unlimited.
const MAX_FINITE_LIMIT: u32 = DW_TASK_GROUP_LIMIT_UNLIMITED - 1;

/// How the budget was reached, and why it fell back, as WRLJ MEMORY
/// reports them.
pub use wyrmroot_launch_proto::{MemoryFallback as FallbackCause, MemorySource as JobMemorySource};

/// What init computed, kept for the boot and reported by `memory`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobMemoryPlan {
    /// Free frames when init read the topic; zero if it could not.
    pub free_pages: u64,
    /// The residents' reserve; zero if free could not be read.
    pub reserve_pages: u64,
    /// The config's cap in pages; zero for none or no config.
    pub cap_pages: u64,
    /// The jobs group's MEMORY_PAGES limit.
    pub jobs_limit_pages: u32,
    /// Each job's MEMORY_PAGES limit.
    pub job_budget_pages: u32,
    pub source: JobMemorySource,
    pub cause: FallbackCause,
}

impl JobMemoryPlan {
    /// The 16 MiB plan, keeping whatever was learned before `cause`.
    const fn fallback(
        free_pages: u64,
        reserve_pages: u64,
        cap_pages: u64,
        cause: FallbackCause,
    ) -> Self {
        Self {
            free_pages,
            reserve_pages,
            cap_pages,
            // What `MAX_SHELL_JOBS` jobs of 16 MiB could reach together.
            jobs_limit_pages: FALLBACK_JOB_MEMORY_PAGES * MAX_SHELL_JOBS as u32,
            job_budget_pages: FALLBACK_JOB_MEMORY_PAGES,
            source: JobMemorySource::Fallback,
            cause,
        }
    }

    /// Each job's budget in bytes, as its INIT carries it.
    pub const fn job_budget_bytes(&self) -> u64 {
        self.job_budget_pages as u64 * PAGE_BYTES
    }
}

const fn saturate(pages: u64) -> u32 {
    if pages > MAX_FINITE_LIMIT as u64 {
        MAX_FINITE_LIMIT
    } else {
        pages as u32
    }
}

/// Plans the budget from the free count init read (or why it could not)
/// and the platform config (or why there is none).
pub fn plan_job_memory(
    free_pages: Result<u64, FallbackCause>,
    config: Result<PlatformConfig, FallbackCause>,
) -> JobMemoryPlan {
    let cap_pages = config.map_or(0, |config| config.job_memory_bytes_max / PAGE_BYTES);
    let free_pages = match free_pages {
        Ok(0) => return JobMemoryPlan::fallback(0, 0, cap_pages, FallbackCause::NoFreeCount),
        Ok(free) => free,
        Err(cause) => return JobMemoryPlan::fallback(0, 0, cap_pages, cause),
    };
    let config = match config {
        Ok(config) => config,
        Err(cause) => {
            let reserve = default_reserve(free_pages);
            return JobMemoryPlan::fallback(free_pages, reserve, 0, cause);
        }
    };
    let reserve_pages = match config.resident_reserve_bytes / PAGE_BYTES {
        0 => default_reserve(free_pages),
        reserve => reserve,
    };
    let available = free_pages.saturating_sub(reserve_pages);
    let half = available / 2;
    if half == 0 {
        return JobMemoryPlan::fallback(
            free_pages,
            reserve_pages,
            cap_pages,
            FallbackCause::FreeNotAboveReserve,
        );
    }
    let (budget, source) = if cap_pages != 0 && cap_pages < half {
        (cap_pages, JobMemorySource::Capped)
    } else {
        (half, JobMemorySource::Computed)
    };
    JobMemoryPlan {
        free_pages,
        reserve_pages,
        cap_pages,
        jobs_limit_pages: saturate(available),
        job_budget_pages: saturate(budget),
        source,
        cause: FallbackCause::None,
    }
}

/// The larger of 256 MiB and one eighth of free.
const fn default_reserve(free_pages: u64) -> u64 {
    let eighth = free_pages / 8;
    if eighth > DEFAULT_RESERVE_FLOOR_PAGES {
        eighth
    } else {
        DEFAULT_RESERVE_FLOOR_PAGES
    }
}

/// Reads the platform config from bootfs, or says why there is none.
pub fn read_platform_config(bootfs: &[u8]) -> Result<PlatformConfig, FallbackCause> {
    let archive = Archive::new(bootfs).map_err(|_| FallbackCause::ConfigMalformed)?;
    let entry = match archive.lookup(PLATFORM_CONFIG_PATH.as_bytes()) {
        Ok(entry) => entry,
        Err(wyrmroot_bootfs::archive::LookupError::NotFound) => {
            return Err(FallbackCause::ConfigMissing);
        }
        Err(_) => return Err(FallbackCause::ConfigMalformed),
    };
    if entry.is_executable() {
        return Err(FallbackCause::ConfigMalformed);
    }
    PlatformConfig::parse(entry.data()).map_err(|_| FallbackCause::ConfigMalformed)
}

/// The plan and the jobs group every job's group is created under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JobMemory {
    pub(crate) plan: JobMemoryPlan,
    /// Absent only when it could not be made ([`FallbackCause::JobsGroup`]);
    /// jobs then go under init's own group at 16 MiB each.
    pub(crate) jobs_group: Option<DwHandle>,
    /// Init's own group, the root, whose free count `memory` reads again.
    pub(crate) init_group: DwHandle,
}

impl JobMemory {
    /// Before init has planned: no job may launch yet, so this is never
    /// read for a launch; it is the 16 MiB plan with no group.
    pub(crate) const UNPLANNED: Self = Self {
        plan: JobMemoryPlan::fallback(0, 0, 0, FallbackCause::TopicUnreadable),
        jobs_group: None,
        init_group: DwHandle(0),
    };

    /// The group a new job's group goes under.
    pub(crate) fn job_parent(&self, init_group: DwHandle) -> DwHandle {
        self.jobs_group.unwrap_or(init_group)
    }

    /// The jobs group's usage in pages now, if it can be read.
    pub(crate) fn jobs_usage<P: JobGroupPlatform>(&self, system: &mut P) -> Option<u64> {
        let group = self.jobs_group?;
        system
            .query_task_group_memory(group)
            .ok()
            .map(|info| info.usage)
    }

    /// The plan with what the jobs group and the machine hold now. A read
    /// that fails reports zero rather than failing the query. The jobs limit
    /// is the one the kernel holds on the jobs group, read now, so a limit
    /// applied differently from the plan shows (step-5 review D3); without a
    /// jobs group it is the plan's.
    pub(crate) fn report<P: JobGroupPlatform>(&self, system: &mut P) -> MemoryReport {
        let jobs = self
            .jobs_group
            .map(|group| system.query_task_group_memory(group).ok());
        let jobs_usage_pages = jobs.flatten().map_or(0, |info| info.usage);
        let jobs_limit_pages = match jobs {
            Some(read) => read.map_or(0, |info| u64::from(info.limit)),
            None => u64::from(self.plan.jobs_limit_pages),
        };
        let free_pages_now = system
            .query_task_group_memory(self.init_group)
            .map_or(0, |info| info.free_pages);
        MemoryReport {
            job_budget_pages: u64::from(self.plan.job_budget_pages),
            jobs_limit_pages,
            jobs_usage_pages,
            free_pages_at_plan: self.plan.free_pages,
            free_pages_now,
            reserve_pages: self.plan.reserve_pages,
            cap_pages: self.plan.cap_pages,
            source: self.plan.source,
            fallback: self.plan.cause,
        }
    }
}

/// The longest init holds launches back after ending a job: half the
/// shell's one-second wait for a launch reply (DW2 §10.10 item 7).
pub(crate) const SETTLE_LIMIT_NS: u64 = 500_000_000;
/// The least time between two reads of the jobs group's usage while
/// settling, so two reads a moment apart do not look like a stop.
pub(crate) const SETTLE_SAMPLE_NS: u64 = 20_000_000;

/// The pause after a job init ended has exited (DW2 §10.10 item 7; Mike's
/// bounded park, 2026-11-14). The kernel tears an exited job's address
/// space down in steps, so the jobs group's usage falls for a while after
/// the exit. Until it stops falling, or [`SETTLE_LIMIT_NS`] has passed,
/// init reads no new request from any session, so the next job does not
/// start against memory still owed teardown. Everything else goes on:
/// peer closes, reaping, parked launches and WAIT replies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Settle {
    usage: u64,
    sampled_ns: u64,
    until_ns: u64,
}

impl Settle {
    /// A pause begun at `now_ns` with the usage just read; none if it could
    /// not be read (a failed read never holds launches back). `running` is
    /// the pause already under way, if any: the new one keeps its end, so
    /// jobs reaped one after another cannot hold requests back for longer
    /// than one [`SETTLE_LIMIT_NS`] without a poll that reads them
    /// (step-5 review R1).
    pub(crate) fn begin(running: Option<Self>, usage: Option<u64>, now_ns: u64) -> Option<Self> {
        Some(Self {
            usage: usage?,
            sampled_ns: now_ns,
            until_ns: running.map_or(now_ns.saturating_add(SETTLE_LIMIT_NS), |running| {
                running.until_ns
            }),
        })
    }

    /// The pause at `now_ns`, or none once it is over. `read` reads the
    /// usage; it is called only when a sample is due.
    pub(crate) fn poll(self, now_ns: u64, read: impl FnOnce() -> Option<u64>) -> Option<Self> {
        if now_ns >= self.until_ns {
            return None;
        }
        if now_ns < self.sampled_ns.saturating_add(SETTLE_SAMPLE_NS) {
            return Some(self);
        }
        let usage = read()?;
        (usage < self.usage).then_some(Self {
            usage,
            sampled_ns: now_ns,
            ..self
        })
    }
}

/// What [`establish`] needs from the system: the four calls it makes.
pub(crate) trait JobGroupPlatform {
    fn query_task_group_memory(
        &mut self,
        group: DwHandle,
    ) -> Result<DwTaskGroupMemoryInfoV1, NativeError>;
    fn create_task_group(&mut self, parent: DwHandle) -> Result<DwHandle, NativeError>;
    fn limit_task_group(
        &mut self,
        group: DwHandle,
        class: u32,
        limit: u32,
    ) -> Result<(), NativeError>;
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
}

/// [`JobGroupPlatform`] over init's own platform.
pub(crate) struct InitJobGroups<'a, S>(pub(crate) &'a mut S);

impl<S: InitPlatform> JobGroupPlatform for InitJobGroups<'_, S> {
    fn query_task_group_memory(
        &mut self,
        group: DwHandle,
    ) -> Result<DwTaskGroupMemoryInfoV1, NativeError> {
        self.0.query_task_group_memory(group)
    }
    fn create_task_group(&mut self, parent: DwHandle) -> Result<DwHandle, NativeError> {
        self.0.create_attempt_task_group(parent)
    }
    fn limit_task_group(
        &mut self,
        group: DwHandle,
        class: u32,
        limit: u32,
    ) -> Result<(), NativeError> {
        self.0.limit_task_group(group, class, limit)
    }
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.0.close_handle(handle)
    }
}

/// Plans the budget and makes the jobs group under `init_group`. Only a
/// failure to close a half-made jobs group is an error; every other failure
/// is a fallback plan.
pub(crate) fn establish<P: JobGroupPlatform>(
    system: &mut P,
    init_group: DwHandle,
    bootfs: &[u8],
) -> Result<JobMemory, InitError> {
    let free = system
        .query_task_group_memory(init_group)
        .map(|info| info.free_pages)
        .map_err(|_| FallbackCause::TopicUnreadable);
    let plan = plan_job_memory(free, read_platform_config(bootfs));
    let group = match system.create_task_group(init_group) {
        Ok(group) => group,
        Err(_) => return Ok(jobs_group_failed(plan, init_group)),
    };
    if system
        .limit_task_group(
            group,
            DW_TASK_GROUP_LIMIT_MEMORY_PAGES,
            plan.jobs_limit_pages,
        )
        .is_err()
    {
        system.close_handle(group).map_err(|_| InitError::Cleanup)?;
        return Ok(jobs_group_failed(plan, init_group));
    }
    Ok(JobMemory {
        plan,
        jobs_group: Some(group),
        init_group,
    })
}

fn jobs_group_failed(plan: JobMemoryPlan, init_group: DwHandle) -> JobMemory {
    JobMemory {
        plan: JobMemoryPlan::fallback(
            plan.free_pages,
            plan.reserve_pages,
            plan.cap_pages,
            FallbackCause::JobsGroup,
        ),
        jobs_group: None,
        init_group,
    }
}

#[cfg(test)]
#[path = "job_memory/tests.rs"]
mod tests;
