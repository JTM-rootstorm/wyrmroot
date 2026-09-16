//! The DW1-F/WYR1-F final closure episode.
//!
//! One declared, test-only, post-console normal-activation failure, frozen by
//! `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.4 and implemented only in the
//! instrumented init artifact. It is compiled out of the production build
//! entirely: nothing in this module exists in the artifact `wyr1f prepare
//! --scenario normal` produces.
//!
//! What it does *not* do is as important as what it does. It never fails a
//! role itself, never sets `SystemMode`, never records evidence, never touches
//! a deadline and never counts an attempt. It produces exactly one thing: the
//! ordinary `RecoverDevmgr` outcome that a real publication-observer failure
//! produces, once, after the exact READY join — and then refuses each
//! replacement activation until the supervisor's own finite policy exhausts.
//! Every transition, every retry, every deadline and the `DEGRADED_RECOVERY`
//! result itself stay with `SystemInit`, which is what §5.4 means by "the
//! reached path, not a new one".

use crate::gate::{GateContract, GateScenario};

/// One episode per boot, and only ever forwards.
///
/// `Armed` is reached exactly once, from the exact READY join. `Firing` is
/// reached exactly once, from `Armed`. `Complete` is terminal. Repeated
/// delivery of any trigger therefore cannot reset retry or deadline state,
/// open a second episode, or create another owner: there is no edge back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    /// The scenario is `normal`, or the gate names another contract. Inert for
    /// the whole boot; no edge leaves this state.
    Inert,
    /// Declared, but the console/shell join has not been observed.
    Waiting,
    /// The join was observed. The next poll fires.
    Armed,
    /// The episode is in flight: the supervisor is cycling devmgr and every
    /// activation is refused.
    Firing,
    /// The supervisor reached its own terminal result. Nothing fires again.
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClosureEpisode {
    phase: Phase,
}

impl ClosureEpisode {
    /// Reads the declared scenario from the already-parsed gate configuration.
    ///
    /// The contract *pair* is checked, not just the scenario: a selector-25
    /// `permanent-supervisor-rrc` configuration names a historical WYR1-A
    /// regression, and admitting it here would let that product drive the
    /// final closure episode.
    pub(crate) const fn new(gate: Option<crate::gate::GateConfig>) -> Self {
        let phase = match gate {
            Some(config) => match (config.contract, config.scenario) {
                (GateContract::Dw1Wyr1InteractiveClosure, GateScenario::DegradedRecovery) => {
                    Phase::Waiting
                }
                _ => Phase::Inert,
            },
            None => Phase::Inert,
        };
        Self { phase }
    }

    /// Test-only introspection. The episode's whole production surface is
    /// `observe_ready_join`, `take_trigger`, `refuses_activation` and
    /// `observe_terminal`; these two exist so the tests can tell `Inert` from
    /// `Waiting` and `Complete` from `Waiting`, which no caller needs to.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn is_declared(&self) -> bool {
        !matches!(self.phase, Phase::Inert)
    }

    /// Observes the exact full-console READY join.
    ///
    /// Both halves are required and are supplied by their own owners:
    /// `console_ready` by the consoled READY validation in `wyr1e_native`, and
    /// `shell_ready` by the first `system/wyrmsh` generation reaching
    /// `JobDispatchOutcome::Launched` in `wyr1b_native`. Neither is derived
    /// from a shell command, from COM2 text, or from a printed string.
    ///
    /// Calling this with a partial join, or repeatedly after the join, changes
    /// nothing: only `Waiting` has an outgoing edge, and only a complete join
    /// takes it.
    pub(crate) const fn observe_ready_join(&mut self, console_ready: bool, shell_ready: bool) {
        if matches!(self.phase, Phase::Waiting) && console_ready && shell_ready {
            self.phase = Phase::Armed;
        }
    }

    /// Takes the one trigger, if it is due.
    ///
    /// Returns `true` at most once per boot, and never before the join.
    pub(crate) const fn take_trigger(&mut self) -> bool {
        if matches!(self.phase, Phase::Armed) {
            self.phase = Phase::Firing;
            true
        } else {
            false
        }
    }

    /// Whether a devmgr activation attempt is refused by the episode in
    /// flight. Outside `Firing` this is always `false`, so the normal
    /// scenario, a pre-join poll and a finished episode all activate
    /// ordinarily.
    #[must_use]
    pub(crate) const fn refuses_activation(&self) -> bool {
        matches!(self.phase, Phase::Firing)
    }

    /// Closes the episode once the supervisor has reached its own terminal
    /// result. After this nothing fires and nothing is refused, so the
    /// bounded admin path and ordinary shell replacement run untouched.
    pub(crate) const fn observe_terminal(&mut self) {
        if matches!(self.phase, Phase::Firing) {
            self.phase = Phase::Complete;
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn is_complete(&self) -> bool {
        matches!(self.phase, Phase::Complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::GateConfig;

    const fn config(contract: GateContract, scenario: GateScenario) -> Option<GateConfig> {
        Some(GateConfig {
            contract,
            scenario,
            nonce: 0xff,
        })
    }

    fn degraded() -> ClosureEpisode {
        ClosureEpisode::new(config(
            GateContract::Dw1Wyr1InteractiveClosure,
            GateScenario::DegradedRecovery,
        ))
    }

    /// The whole of the normal product's relationship with this module.
    #[test]
    fn nothing_is_declared_without_the_exact_contract_and_scenario_pair() {
        for inert in [
            None,
            config(
                GateContract::Dw1Wyr1InteractiveClosure,
                GateScenario::Normal,
            ),
            config(
                GateContract::PermanentSupervisorRrc,
                GateScenario::DegradedRecovery,
            ),
            config(GateContract::PermanentSupervisorRrc, GateScenario::Normal),
        ] {
            let mut episode = ClosureEpisode::new(inert);
            assert!(!episode.is_declared());
            episode.observe_ready_join(true, true);
            assert!(!episode.take_trigger());
            assert!(!episode.refuses_activation());
        }
    }

    #[test]
    fn the_trigger_is_refused_before_the_exact_join() {
        for (console, shell) in [(false, false), (true, false), (false, true)] {
            let mut episode = degraded();
            episode.observe_ready_join(console, shell);
            assert!(!episode.take_trigger());
            assert!(!episode.refuses_activation());
        }
    }

    #[test]
    fn one_episode_per_boot_survives_repeated_delivery() {
        let mut episode = degraded();
        episode.observe_ready_join(true, true);
        assert!(episode.take_trigger());
        // Polling does not fire a second time, and re-observing the join does
        // not re-arm: the episode in flight keeps refusing, and that is all.
        for _ in 0..8 {
            episode.observe_ready_join(true, true);
            assert!(!episode.take_trigger());
            assert!(episode.refuses_activation());
        }
        episode.observe_terminal();
        assert!(episode.is_complete());
        // A late or stale trigger after the terminal result does nothing, and
        // activation is no longer refused.
        for _ in 0..8 {
            episode.observe_ready_join(true, true);
            assert!(!episode.take_trigger());
            assert!(!episode.refuses_activation());
        }
    }

    /// The named item's source span, for the two structural checks below.
    fn item<'a>(source: &'a str, signature: &'a str) -> &'a str {
        let start = source.find(signature).expect(signature);
        let body = &source[start..];
        let open = body.find('{').expect("body");
        let mut depth = 0_usize;
        for (index, byte) in body.as_bytes().iter().enumerate().skip(open) {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &body[..=index];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced body for {signature}");
    }

    /// F1B.4: "old READY or endpoint tuple used as full-console trigger".
    ///
    /// The closure episode's READY join is read from the two owners' live state,
    /// not from a recorded tuple. There is nothing for a stale generation, a stale
    /// endpoint or a replayed READY message to be presented as, because the join
    /// carries no identity at all -- only "consoled is installed and validated"
    /// and "a wyrmsh generation has reached READY".
    ///
    /// The shell half is deliberately never cleared: it means "the first
    /// generation was READY", not "a generation is READY now", so a shell that
    /// exits and is replaced after DEGRADED cannot re-arm an episode.
    #[test]
    fn the_closure_ready_join_reads_live_owner_state_and_no_tuple() {
        let join = item(
            include_str!("wyr1e_native.rs"),
            "pub(super) fn wyr1f_ready_join",
        );
        assert!(join.contains("e6.console.is_some() && !e6.awaiting_ready"));
        assert!(join.contains("e6.shell.wyr1f_shell_ready()"));
        for forbidden in [
            "generation",
            "endpoint",
            "transaction",
            "identity",
            "nonce",
            "tuple",
        ] {
            assert!(
                !join.contains(forbidden),
                "the join must carry no {forbidden}: an identity here is \
                 something a stale one could be presented as"
            );
        }
        // The shell half is set and never cleared: it means "the first
        // generation was READY", not "a generation is READY now", so a shell
        // replaced after DEGRADED cannot re-arm an episode.
        let shell = include_str!("wyr1b_native.rs");
        assert!(shell.contains("self.wyr1f_shell_ready = true;"));
        assert!(!shell.contains("self.wyr1f_shell_ready = false;"));
    }

    /// F1B.4: "extra method/right/handle added to shell or job".
    ///
    /// The episode adds no shell or job surface at all. It is confined to init:
    /// one observation recorded by the dispatcher at a join it already computed,
    /// and one state machine on the resident. Nothing reaches `wyr1b_job`, and the
    /// shell and job profiles are whatever they were -- which is why the matched
    /// siblings' launch policies are byte-identical.
    /// F1B.4: "extra method/right/handle added to shell or job".
    ///
    /// The episode adds no shell or job surface at all. It is confined to
    /// init: one boolean recorded by the dispatcher at a join it already
    /// computes, and one state machine on the resident. Nothing reaches
    /// `wyr1b_job`, and the shell and job profiles are whatever they were --
    /// which is why the matched siblings' launch policies are byte-identical.
    #[test]
    fn the_closure_episode_adds_no_shell_or_job_authority() {
        let jobs = include_str!("wyr1b_job.rs");
        assert!(!jobs.contains("wyr1f"));
        let shell = include_str!("wyr1b_native.rs");
        // The field, its initializer, one setter, one reader, and one call at
        // the join the dispatcher already computes. A shell surface would need
        // more than a boolean.
        assert_eq!(shell.matches("wyr1f_shell_ready").count(), 7);
        assert_eq!(shell.matches("observe_wyr1f_shell_ready").count(), 2);
        // The episode type appears in `wyr1b_native` only where a
        // `ResidentSystemInit` is constructed, which is init's own field. The
        // shell controller neither holds it nor can reach it.
        assert_eq!(shell.matches("ClosureEpisode").count(), 2);
        assert_eq!(shell.matches("ClosureEpisode::new(").count(), 2);
        for span in [
            item(shell, "pub(crate) struct ShellControllerState"),
            item(shell, "impl ShellControllerState"),
        ] {
            assert!(!span.contains("ClosureEpisode"));
            assert!(!span.contains("wyr1f_closure"));
        }
        // The episode itself never names a launch profile, a right or a
        // handle, and contains no `unsafe`. Scanned above `#[cfg(test)]`,
        // because this test names those very words a few lines down.
        let whole = include_str!("wyr1f_closure.rs");
        let episode = &whole[..whole.find("#[cfg(test)]").expect("test module")];
        for forbidden in ["LaunchProfile", "DwRights", "DwHandle", "Channel", "unsafe"] {
            assert!(
                !episode.contains(forbidden),
                "episode must not name {forbidden}"
            );
        }
    }

    /// A terminal observation that arrives before the episode is in flight is
    /// some other role's, and must not consume the declared episode.
    #[test]
    fn a_terminal_result_outside_the_episode_does_not_close_it() {
        let mut episode = degraded();
        episode.observe_terminal();
        assert!(!episode.is_complete());
        episode.observe_ready_join(true, true);
        assert!(episode.take_trigger());
        assert!(episode.refuses_activation());
    }
}
