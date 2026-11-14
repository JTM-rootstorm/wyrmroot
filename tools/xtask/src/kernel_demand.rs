//! The product's demand on the kernel's pools (root
//! `OS_STACK_ARCHITECTURE_PLAN.md` C1).
//!
//! Deepwyrm once carried this ledger as a census of Wyrmroot's roles, so a
//! new service was a kernel edit. The kernel now publishes only its
//! capacities, in `kernel/arch/x86_64/pools.toml`; the product build reads
//! that file from the paired checkout and refuses a product whose demand does
//! not fit, naming the pool. A new role is an edit here.
//!
//! Every pool is sized by a *simultaneous* peak: the kernel's tables are
//! occupancy bounds and a finalized generation releases its slot. Recovery is
//! production behaviour, so the peaks carry one replacement generation
//! overlapping the one it replaces.
//!
//! The arithmetic was moved unchanged from Deepwyrm's
//! `production_resource_geometry.rs` (Deepwyrm before `679fb3d`), whose
//! history records how each row was found.

use std::fs;
use std::path::Path;

use crate::error::Failure;

pub(crate) const POOLS_PATH: &str = "kernel/arch/x86_64/pools.toml";
const POOLS_SCHEMA: &str = "deepwyrm-x86_64-pools";
const MAX_POOLS_BYTES: u64 = 16 * 1024;

/// The kernel's capacities, as `pools.toml` states them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelPools {
    pub(crate) handles_per_process: usize,
    pub(crate) identities: usize,
    pub(crate) registry_objects: usize,
    pub(crate) memory_objects: usize,
    pub(crate) mapping_leases: usize,
    pub(crate) region_slots: usize,
    pub(crate) channel_pairs: usize,
    pub(crate) channel_depth: usize,
    pub(crate) wait_registrations: usize,
    pub(crate) timers: usize,
    pub(crate) events: usize,
}

const POOL_KEYS: [&str; 11] = [
    "handles_per_process",
    "identities",
    "registry_objects",
    "memory_objects",
    "mapping_leases",
    "region_slots",
    "channel_pairs",
    "channel_depth",
    "wait_registrations",
    "timers",
    "events",
];

/// Strictly parses `pools.toml`: the schema and version lines and each pool
/// key exactly once, as a nonzero 32-bit decimal count.
pub(crate) fn parse_pools(contents: &str) -> Result<KernelPools, String> {
    let mut schema = None;
    let mut version = None;
    let mut values = [None; POOL_KEYS.len()];
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once(" = ")
            .ok_or_else(|| "has a malformed line".to_owned())?;
        let slot = match key {
            "schema" => &mut schema,
            "version" => &mut version,
            _ => {
                let index = POOL_KEYS
                    .iter()
                    .position(|known| *known == key)
                    .ok_or_else(|| format!("has an unsupported key `{key}`"))?;
                &mut values[index]
            }
        };
        if slot.replace(value).is_some() {
            return Err(format!("repeats key `{key}`"));
        }
    }
    if schema != Some(&format!("\"{POOLS_SCHEMA}\"")) {
        return Err(format!("does not name schema \"{POOLS_SCHEMA}\""));
    }
    if version != Some("1") {
        return Err("is not version 1".to_owned());
    }
    let mut counts = [0_usize; POOL_KEYS.len()];
    for ((count, value), key) in counts.iter_mut().zip(values).zip(POOL_KEYS) {
        let value = value.ok_or_else(|| format!("is missing `{key}`"))?;
        *count = value
            .parse::<u32>()
            .ok()
            .filter(|count| *count > 0 && !value.starts_with('+'))
            .ok_or_else(|| format!("`{key}` is not a nonzero 32-bit count"))?
            as usize;
    }
    let [
        handles_per_process,
        identities,
        registry_objects,
        memory_objects,
        mapping_leases,
        region_slots,
        channel_pairs,
        channel_depth,
        wait_registrations,
        timers,
        events,
    ] = counts;
    Ok(KernelPools {
        handles_per_process,
        identities,
        registry_objects,
        memory_objects,
        mapping_leases,
        region_slots,
        channel_pairs,
        channel_depth,
        wait_registrations,
        timers,
        events,
    })
}

/// Reads the paired checkout's pools and refuses the product when its demand
/// does not fit them.
pub(crate) fn require(deep_repository: &Path) -> Result<KernelPools, Failure> {
    let path = deep_repository.join(POOLS_PATH);
    let refused = |reason: String| {
        Failure::task(format!(
            "the Deepwyrm checkout at {} cannot host this product: {reason}",
            deep_repository.display()
        ))
    };
    let parent = path
        .parent()
        .and_then(|parent| fs::canonicalize(parent).ok())
        .ok_or_else(|| refused(format!("it has no {POOLS_PATH}")))?;
    if path.parent() != Some(parent.as_path()) {
        return Err(refused(format!(
            "{POOLS_PATH} does not resolve inside the checkout"
        )));
    }
    let bytes = crate::product::read_regular_bounded(&path, MAX_POOLS_BYTES, "the kernel pools")
        .map_err(|failure| refused(failure.message))?;
    let contents =
        String::from_utf8(bytes).map_err(|_| refused(format!("{POOLS_PATH} is not UTF-8")))?;
    let pools =
        parse_pools(&contents).map_err(|message| refused(format!("{POOLS_PATH} {message}")))?;
    let short = shortfalls(&pools, &Demand::PRODUCT);
    if !short.is_empty() {
        return Err(refused(format!(
            "its pools are smaller than this product's peak demand: {}. Raise them in \
             {POOLS_PATH} (and check `xtask kernel-check` there), or shrink the product.",
            short.join("; ")
        )));
    }
    Ok(pools)
}

/// The product's simultaneous peak on each pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Demand {
    pub(crate) handles: usize,
    pub(crate) identities: usize,
    pub(crate) registry_objects: usize,
    pub(crate) memory_objects: usize,
    /// Mappings outside the jobs; each job adds one per region slot.
    pub(crate) mappings_outside_jobs: usize,
    pub(crate) live_jobs: usize,
    pub(crate) region_mappings: usize,
    pub(crate) channel_pairs: usize,
    pub(crate) wait_registrations: usize,
    pub(crate) timers: usize,
    pub(crate) events: usize,
}

impl Demand {
    pub(crate) const PRODUCT: Self = Self {
        handles: HANDLE_PEAK,
        identities: LIVE_IDENTITY_PEAK,
        registry_objects: REGISTRY_PEAK,
        memory_objects: MEMORY_PEAK,
        mappings_outside_jobs: MEMORY_PEAK
            - LIVE_SHELL_JOBS * (JOB_IMAGE_OBJECTS + JOB_OWN_MEMORY_OBJECTS),
        live_jobs: LIVE_SHELL_JOBS,
        region_mappings: REGION_MAPPING_PEAK,
        channel_pairs: CHANNEL_PAIR_PEAK,
        wait_registrations: WAIT_PEAK,
        timers: TIMER_PEAK,
        events: EVENT_PEAK,
    };

    /// Every object outside the jobs holds one lease; a job holds at most one
    /// per mapping slot of its one region, however many objects it has (DW2
    /// M5 design review, finding 11). So the peak depends on the slots.
    pub(crate) const fn mapping_peak(&self, region_slots: usize) -> usize {
        self.mappings_outside_jobs + self.live_jobs * region_slots
    }
}

/// Each pool the demand exceeds, as `name: demand > capacity`.
pub(crate) fn shortfalls(pools: &KernelPools, demand: &Demand) -> Vec<String> {
    let rows = [
        (
            "handles_per_process",
            demand.handles,
            pools.handles_per_process,
        ),
        ("identities", demand.identities, pools.identities),
        (
            "registry_objects",
            demand.registry_objects,
            pools.registry_objects,
        ),
        (
            "memory_objects",
            demand.memory_objects,
            pools.memory_objects,
        ),
        (
            "mapping_leases",
            demand.mapping_peak(pools.region_slots),
            pools.mapping_leases,
        ),
        ("region_slots", demand.region_mappings, pools.region_slots),
        ("channel_pairs", demand.channel_pairs, pools.channel_pairs),
        (
            "wait_registrations",
            demand.wait_registrations,
            pools.wait_registrations,
        ),
        ("timers", demand.timers, pools.timers),
        ("events", demand.events, pools.events),
    ];
    rows.into_iter()
        .filter(|(_, demand, capacity)| demand > capacity)
        .map(|(name, demand, capacity)| format!("{name}: {demand} > {capacity}"))
        .collect()
}

// The six interactive roles' handles in init: its own four authorities;
// registryd Process/TaskGroup/bootstrap/control; devmgr Process/bootstrap/
// publication; UART Process/bootstrap/control; consoled Process/bootstrap/
// registry/launch; shell Process/TaskGroup/job endpoint.
const INIT_RESIDENT_HANDLES: [usize; 6] = [4, 4, 3, 3, 4, 3];
/// Init holds each disk driver's Process, launch Channel and TaskGroup, and
/// each storage service's Process, launch Channel, TaskGroup and control
/// Channel.
const STORAGE_DRIVERS: usize = 2;
const STORAGE_SERVICES: usize = 5;
const INIT_STORAGE_HANDLES: usize = STORAGE_DRIVERS * 3 + STORAGE_SERVICES * 4;
/// A shell `run` of a file is read across ticks: init holds the request's
/// five handles (three streams, the file's Channel and the job's namespace),
/// the memory object the request bytes wait in, and the private memory it
/// reads the image into.
const IMAGE_LAUNCH_HANDLES: usize = 5 + 1 + 1;
/// While an image read is parked init keeps serving other sessions, and one
/// receive delivers up to a request's five handles before any is closed or
/// placed. Init treats a handle table too full to receive as its own failure
/// (Mike, 2026-11-13: accepted until C3), so this headroom is what keeps a
/// client from causing it.
const REQUEST_RECEIVE_HANDLES: usize = 5;
const INIT_BASELINE_HANDLES: usize = sum(&INIT_RESIDENT_HANDLES) + INIT_STORAGE_HANDLES;

/// The six interactive roles and the seven storage roles.
const RESIDENT_IMAGES: usize = 6 + STORAGE_DRIVERS + STORAGE_SERVICES;
/// PT_LOADs plus the initial stack.
const RESIDENT_IMAGE_OBJECTS: usize = 2 + 1;
/// The loader refuses a job image with more PT_LOADs than this.
const JOB_IMAGE_OBJECTS: usize = wyrmroot_loader::elf::MAX_JOB_LOAD_SEGMENTS + 1;
/// Each disk driver's BAR object and DMA object; fat32d's and ext4d's
/// attached buffers; each blockmgr's discovery buffer; init's private copy of
/// a file being launched.
const STORAGE_MEMORY: usize = STORAGE_DRIVERS * 2 + 2 + 2 + 1;
const BASELINE_MEMORY: usize = RESIDENT_IMAGES * RESIDENT_IMAGE_OBJECTS + 1 + STORAGE_MEMORY; // + bootfs.

/// A replacement generation is constructed before the generation it replaces
/// is reaped, and init's recovery is serialized per role: one at a time.
const REPLACEMENT_GENERATIONS: usize = 1;
/// Concurrent shell jobs, orphans included; init refuses a launch beyond its
/// `MAX_SHELL_JOBS`.
const LIVE_SHELL_JOBS: usize = 4;
/// The wait items, MemoryObjects and Channel pairs one job may create itself
/// (init's `JOB_TASK_GROUP_LIMITS`): a small wait-many, `mmap` objects whose
/// RAM the MEMORY_PAGES limit bounds, and a sleeping pair plus one per open
/// file.
const JOB_OWN_WAITS: usize = 4;
const JOB_OWN_MEMORY_OBJECTS: usize = 64;
const JOB_OWN_CHANNEL_PAIRS: usize = 5;
/// Init holds each live job's Process, TaskGroup and launch Channel.
const JOB_HELD_HANDLES: usize = 3;

const LIVE_PROCESSES: usize = RESIDENT_IMAGES + REPLACEMENT_GENERATIONS + LIVE_SHELL_JOBS;
/// The bootstrap root, the long-lived resource domain, and the driver-attempt
/// group, a domain sibling because the driver outlives a devmgr generation.
const STRUCTURAL_TASK_GROUPS: usize = 3;
const LIVE_TASK_GROUPS: usize = LIVE_PROCESSES + STRUCTURAL_TASK_GROUPS;
/// Process, Thread, address space and TaskGroup share one identity pool, so
/// the peak is the larger live count. Primordial has retired by then.
const LIVE_IDENTITY_PEAK: usize = if LIVE_PROCESSES > LIVE_TASK_GROUPS {
    LIVE_PROCESSES
} else {
    LIVE_TASK_GROUPS
};

/// A stream job's loader stage: one attempt TaskGroup, four retained INIT
/// endpoints (three streams and a namespace), the child endpoint, and the
/// broad and reduced parent handles during ChannelReduce.
const STREAM_JOB_LOADER_HANDLES: usize = 1 + 4 + 1 + 2 + 1;
/// A devmgr replacement holds the duplicated resource-domain handle, the
/// reduced handle it will MOVE, and the outgoing generation's Process.
const REPLACEMENT_STAGING_HANDLES: usize = 3;
const HANDLE_PEAK: usize = INIT_BASELINE_HANDLES
    + STREAM_JOB_LOADER_HANDLES
    + IMAGE_LAUNCH_HANDLES
    + REQUEST_RECEIVE_HANDLES
    + REPLACEMENT_STAGING_HANDLES
    + LIVE_SHELL_JOBS * JOB_HELD_HANDLES;
const MEMORY_PEAK: usize = BASELINE_MEMORY
    + REPLACEMENT_GENERATIONS * RESIDENT_IMAGE_OBJECTS
    + LIVE_SHELL_JOBS * (JOB_IMAGE_OBJECTS + JOB_OWN_MEMORY_OBJECTS)
    + 1; // Loader scratch view, open until the child mapping is installed.

/// The interactive graph's pairs: primordial to init, init's five role
/// startups, the service pairs to registryd, devmgr's publication pair, the
/// device control pair, consoled's launch pair and the shell's job pair.
/// Storage: per disk driver its startup, devmgr control and publication
/// pairs; per service its startup and control pairs; three publications; four
/// registry clients; both filesystem roots to vfsd; each filesystem's volume
/// connection and blockmgr's driver connection; a shell's vfsd connection
/// with two open nodes.
const STORAGE_CHANNEL_PAIRS: usize =
    STORAGE_DRIVERS * 3 + STORAGE_SERVICES * 2 + 3 + 4 + 2 + 2 * 2 + 3;
const BASELINE_CHANNEL_PAIRS: usize = 17 + STORAGE_CHANNEL_PAIRS;
/// A replacement generation's startup, control and publication pairs.
const REPLACEMENT_CHANNEL_PAIRS: usize = 3;
/// Three stream pairs, a startup pair and a namespace connection per job, and
/// the pairs the job creates itself.
const JOB_CHANNEL_PAIRS: usize = 3 + 1 + 1 + JOB_OWN_CHANNEL_PAIRS;
const CHANNEL_PAIR_PEAK: usize =
    BASELINE_CHANNEL_PAIRS + REPLACEMENT_CHANNEL_PAIRS + LIVE_SHELL_JOBS * JOB_CHANNEL_PAIRS;
/// Both endpoints of every pair are registry objects.
const CHANNEL_ENDPOINT_PEAK: usize = 2 * CHANNEL_PAIR_PEAK;

/// The boot resource domain, the UART's DeviceResource with its one
/// Interrupt, and the two disks' PCI functions.
const DEVICE_RESOURCES: usize = 1 + STORAGE_DRIVERS;
const INTERRUPTS: usize = 1;
/// The UART pacing Timer and init's resident control tick can overlap.
const TIMER_PEAK: usize = 2;
const EVENT_PEAK: usize = 0;
/// A resident image's PT_LOADs, stack, bootfs and scratch view.
const REGION_MAPPING_PEAK: usize = 2 + 1 + 1 + 1;

const REGISTRY_PEAK: usize = LIVE_PROCESSES * 3 // Process, Thread, root
    + LIVE_TASK_GROUPS
    + MEMORY_PEAK
    + CHANNEL_ENDPOINT_PEAK
    + DEVICE_RESOURCES
    + INTERRUPTS
    + TIMER_PEAK;

/// The six-role interactive graph's waits: the controller's resident
/// supervision set, the registry, device, console, shell and job sets.
const INTERACTIVE_GRAPH_WAITS: usize = 12 + 3 + 4 + 6 + 7 + 7;
/// An exit wait apiece for each live job and the replacement generation,
/// each owning a Channel and a Process registration.
const ADDED_EXIT_WAITS: usize = (LIVE_SHELL_JOBS + REPLACEMENT_GENERATIONS) * 2;
/// The storage roles' wait sets: a disk driver's control, publication and four
/// connections; a blockmgr's control, publication and three two-Channel client
/// links; fat32d's and ext4d's control, root and four nodes; vfsd's control,
/// publication, two mounts, two clients and two nodes; init's exit wait per
/// role.
const STORAGE_WAITS: usize = STORAGE_DRIVERS * 6
    + 2 * (2 + 3 * 2)
    + 2 * (2 + 4)
    + (2 + 2 + 2 + 2)
    + STORAGE_DRIVERS
    + STORAGE_SERVICES;
/// vfsd waits on each live file job's namespace, and on every node the job
/// holds open; every pair the job may create can be a node.
const JOB_NAMESPACE_WAITS: usize = 1;
const JOB_OPEN_NODE_WAITS: usize = JOB_OWN_CHANNEL_PAIRS;
const WAIT_PEAK: usize = INTERACTIVE_GRAPH_WAITS
    + ADDED_EXIT_WAITS
    + LIVE_SHELL_JOBS * (JOB_OWN_WAITS + JOB_NAMESPACE_WAITS + JOB_OPEN_NODE_WAITS)
    + STORAGE_WAITS;

const fn sum(values: &[usize]) -> usize {
    let mut result = 0;
    let mut index = 0;
    while index < values.len() {
        result += values[index];
        index += 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEEPWYRM_POOLS: &str = "schema = \"deepwyrm-x86_64-pools\"\nversion = 1\n\
        handles_per_process = 96\nidentities = 32\nregistry_objects = 640\n\
        memory_objects = 384\nmapping_leases = 320\nregion_slots = 64\n\
        channel_pairs = 96\nchannel_depth = 2\nwait_registrations = 160\n\
        timers = 2\nevents = 1\n";

    #[test]
    fn the_product_s_peaks_are_the_documented_arithmetic() {
        let demand = Demand::PRODUCT;
        assert_eq!(INIT_BASELINE_HANDLES, 47);
        assert_eq!(demand.handles, 83);
        assert_eq!(demand.identities, 21);
        assert_eq!(demand.memory_objects, 321);
        assert_eq!(demand.mapping_peak(64), 309);
        assert_eq!(CHANNEL_PAIR_PEAK, 92);
        assert_eq!(demand.registry_objects, 586);
        assert_eq!(STORAGE_WAITS, 55);
        assert_eq!(demand.wait_registrations, 144);
    }

    #[test]
    fn the_product_fits_the_pools_deepwyrm_ships() {
        let pools = parse_pools(DEEPWYRM_POOLS).unwrap();
        assert_eq!(pools.handles_per_process, 96);
        assert_eq!(pools.region_slots, 64);
        assert_eq!(shortfalls(&pools, &Demand::PRODUCT), Vec::<String>::new());
    }

    #[test]
    fn a_pool_below_the_peak_is_named_with_both_numbers() {
        let pools = KernelPools {
            handles_per_process: 82,
            wait_registrations: 4,
            ..parse_pools(DEEPWYRM_POOLS).unwrap()
        };
        assert_eq!(
            shortfalls(&pools, &Demand::PRODUCT),
            vec![
                "handles_per_process: 83 > 82".to_owned(),
                "wait_registrations: 144 > 4".to_owned(),
            ]
        );
    }

    #[test]
    fn more_region_slots_raise_the_lease_demand() {
        let pools = KernelPools {
            region_slots: 128,
            ..parse_pools(DEEPWYRM_POOLS).unwrap()
        };
        assert_eq!(
            shortfalls(&pools, &Demand::PRODUCT),
            vec!["mapping_leases: 565 > 320".to_owned()]
        );
    }

    #[test]
    fn the_pools_file_is_parsed_strictly() {
        let replace = |from: &str, to: &str| DEEPWYRM_POOLS.replacen(from, to, 1);
        for (bad, reason) in [
            (replace("identities = 32", "identities = 0"), "zero"),
            (replace("identities = 32", "identities = +32"), "signed"),
            (
                replace("identities = 32", "identities = 4294967296"),
                "wide",
            ),
            (replace("identities = 32\n", ""), "missing"),
            (format!("{DEEPWYRM_POOLS}identities = 32\n"), "repeated"),
            (format!("{DEEPWYRM_POOLS}threads = 32\n"), "unknown"),
            (replace("version = 1", "version = 2"), "version"),
            (replace("x86_64-pools", "x86_64-layout"), "schema"),
            (replace("identities = 32", "identities=32"), "spacing"),
        ] {
            assert!(parse_pools(&bad).is_err(), "{reason}");
        }
    }
}
