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

/// The three production roles whose READY `SystemInit`'s controller does not
/// observe itself, in dependency order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BringupRole {
    Uart,
    Console,
    Shell,
}

/// Bring-up READY evidence for the roles `SystemInit` does not activate.
///
/// F3A.7k. The instrumented product owes one WYR1EVID1 `Ready` per production
/// role, in dependency order: registryd, devmgr, uart16550d, consoled,
/// wyrmsh. The controller records the first two when it activates them. The
/// other three become READY on the resident path, at sites that know nothing
/// about the evidence log. Each site reports the first identity it sees here,
/// and the resident tick records them in order.
///
/// Separate from `ClosureEpisode` because the episode never records evidence,
/// and this does nothing else. Only the *first* READY per role counts: the
/// obligation is bring-up, and a shell replaced after `exit` is not bring-up.
/// A role is never handed out before the roles it depends on, so the log's
/// order is the dependency order by construction, not by timing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BringupEvidence {
    observed: [Option<(u64, u64)>; 3],
    recorded: usize,
}

impl BringupEvidence {
    pub(crate) const fn new() -> Self {
        Self {
            observed: [None; 3],
            recorded: 0,
        }
    }

    /// Remembers `role`'s READY identity unless one is already held.
    ///
    /// A zero generation or transaction is not an identity WYR1EVID1 can
    /// carry, so it is not remembered. The role then never records, and the
    /// transcript fails loudly for a missing READY instead of a malformed one.
    pub(crate) const fn observe(&mut self, role: BringupRole, generation: u64, transaction: u64) {
        let slot = role as usize;
        if self.observed[slot].is_none() && generation != 0 && transaction != 0 {
            self.observed[slot] = Some((generation, transaction));
        }
    }

    /// The next role to record, if its READY has been observed.
    #[must_use]
    pub(crate) const fn next_due(&self) -> Option<(crate::RoleId, u64, u64)> {
        let role = match self.recorded {
            0 => crate::RoleId::Uart16550d,
            1 => crate::RoleId::Consoled,
            2 => crate::RoleId::Wyrmsh,
            _ => return None,
        };
        match self.observed[self.recorded] {
            Some((generation, transaction)) => Some((role, generation, transaction)),
            None => None,
        }
    }

    /// Marks the role `next_due` returned as recorded.
    pub(crate) const fn mark_recorded(&mut self) {
        if self.recorded < self.observed.len() {
            self.recorded += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

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
        assert!(shell.contains("if self.wyr1f_shell_ready.is_none() {"));
        assert!(shell.contains("self.wyr1f_shell_ready = Some((generation, transaction));"));
        assert!(!shell.contains("self.wyr1f_shell_ready = None;"));
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
    /// init: one first-READY identity recorded by the dispatcher at a join it
    /// already computes, and one state machine on the resident. Nothing reaches
    /// `wyr1b_job`, and the shell and job profiles are whatever they were --
    /// which is why the matched siblings' launch policies are byte-identical.
    #[test]
    fn the_closure_episode_adds_no_shell_or_job_authority() {
        let jobs = include_str!("wyr1b_job.rs");
        assert!(!jobs.contains("wyr1f"));
        let shell = include_str!("wyr1b_native.rs");
        // The field, its initializer, one setter (which reads the field once
        // to keep the first identity), one reader, and one call at the join
        // the dispatcher already computes. Since F3A.7k the latch holds the
        // first generation's (generation, transaction) instead of `true`, as
        // bring-up READY evidence; it is still two integers and grants
        // nothing. A shell surface would need more than that.
        assert_eq!(shell.matches("wyr1f_shell_ready").count(), 8);
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

    /// F3A.7k. The wiring around `BringupEvidence` lives on the resident path,
    /// which no host test drives, so it is pinned from source: every tick
    /// records what has been observed, the session's end finalizes the log
    /// only after the roles are retired, and each READY site reports before it
    /// hands the outcome back.
    #[test]
    fn the_instrumented_tick_records_bringup_and_finalizes_at_session_end() {
        let squeeze = |text: &str| -> std::string::String {
            text.chars().filter(|c| !c.is_whitespace()).collect()
        };
        let tick = squeeze(include_str!("wyr1c_native.rs"));
        let trigger = tick
            .find("letoutcome=wyr1f_closure_trigger(resident,outcome);")
            .expect("the closure trigger moved");
        let record = tick
            .find("record_wyr1f_bringup(resident)?;")
            .expect("the tick no longer records bring-up evidence");
        let complete = tick
            .find("ifoutcome==wyr1e::PollOutcome::SessionComplete{")
            .expect("the session-complete check moved");
        assert!(trigger < record && record < complete);
        let body = &tick[complete..];
        let body = &body[..body
            .find("}if")
            .expect("the session-complete check never closes")];
        let retire = body
            .find("retire_for_session_shutdown(")
            .expect("no teardown");
        let finalize = body
            .find("finalize_wyr1f_evidence(resident)?;")
            .expect("no terminal");
        let leave = body
            .find("returnOk(resident.controller.mode());")
            .expect("no return");
        assert!(retire < finalize && finalize < leave);

        let poll = squeeze(include_str!("wyr1e_native.rs"));
        let uart = poll
            .find("crate::wyr1f_closure::BringupRole::Uart,")
            .expect("the UART READY is never observed");
        assert!(
            poll[uart..]
                .find("Ok(Some(PollOutcome::LaunchConsole))")
                .is_some()
        );
        let console = poll
            .find("crate::wyr1f_closure::BringupRole::Console,")
            .expect("consoled's READY is never observed");
        let accepted = poll[console..]
            .find("e6.awaiting_ready=false;returnOk(PollOutcome::Stable);")
            .expect("the console observation is not at READY acceptance");
        assert!(
            accepted < 200,
            "the console observation drifted from READY acceptance"
        );
    }

    /// F3A.7k. The product installs the retained gate before building the
    /// episode from it. Before this, only the fixture did, so every real
    /// instrumented boot ran an inert episode with no evidence log.
    #[test]
    fn the_product_installs_the_retained_gate_before_the_episode_reads_it() {
        let squeeze = |text: &str| -> std::string::String {
            text.chars().filter(|c| !c.is_whitespace()).collect()
        };
        let native = squeeze(include_str!("wyr1c_native.rs"));
        let start = native
            .find("pub(crate)fnactivate_in_place<")
            .expect("the resident activation moved");
        let body = &native[start..];
        let lookup = body
            .find(".lookup(crate::gate::GATE_CONFIG_PATH.as_bytes())")
            .expect("the product no longer reads the retained gate");
        let install = body
            .find("manifest.install_wyr1f_gate(gate)?;")
            .expect("the product no longer installs the retained gate");
        let episode = body
            .find("crate::wyr1f_closure::ClosureEpisode::new(manifest.gate_config())")
            .expect("the episode is no longer built from the controller's gate");
        assert!(lookup < install && install < episode);
        let parse = &body[lookup..install];
        assert!(parse.contains("parse_gate_config(entry.data()).map_err(InitError::GateConfig)?"));
    }

    /// F3A.7k. DEGRADED has no devmgr, and the tick used to return before the
    /// console/shell step, so nothing after the episode -- `exit`, the
    /// session end, the terminal evidence -- could ever happen.
    #[test]
    fn the_degraded_tick_still_supervises_the_console_and_shell() {
        let native: std::string::String = include_str!("wyr1c_native.rs")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let absent = native
            .find("letSome(devmgr)=state.devmgrelse{")
            .expect("the devmgr-absent branch moved");
        let branch = &native[absent..absent + 900];
        assert!(
            branch
                .contains("returnwyr1e_resident_step(resident,system,loader,waits,now_ns,false);")
        );
        assert!(
            native.contains("returnwyr1e_resident_step(resident,system,loader,waits,now_ns,true);")
        );
        let step = native
            .find("fnwyr1e_resident_step<")
            .expect("the console/shell step is gone");
        let step = &native[step..];
        let refuse = step
            .find("if!devmgr_present{returnErr(InitError::AbsentState(0x98));}")
            .expect("without devmgr the step no longer refuses devmgr-dependent outcomes");
        let complete = step
            .find("ifoutcome==wyr1e::PollOutcome::SessionComplete{")
            .expect("the step no longer handles a finished session");
        let dispatch = step
            .find("with_bootfs_bytes(")
            .expect("the recovery dispatch moved");
        assert!(complete < refuse && refuse < dispatch);
    }

    fn drain(evidence: &mut BringupEvidence) -> std::vec::Vec<(crate::RoleId, u64, u64)> {
        let mut out = std::vec::Vec::new();
        while let Some(due) = evidence.next_due() {
            out.push(due);
            evidence.mark_recorded();
        }
        out
    }

    #[test]
    fn bringup_records_each_role_once_in_dependency_order() {
        let mut evidence = BringupEvidence::new();
        // The shell arriving first is held until the console and UART have.
        evidence.observe(BringupRole::Shell, 1, 0x30);
        assert_eq!(drain(&mut evidence), []);
        evidence.observe(BringupRole::Console, 1, 0x20);
        assert_eq!(drain(&mut evidence), []);
        evidence.observe(BringupRole::Uart, 1, 0x10);
        assert_eq!(
            drain(&mut evidence),
            [
                (crate::RoleId::Uart16550d, 1, 0x10),
                (crate::RoleId::Consoled, 1, 0x20),
                (crate::RoleId::Wyrmsh, 1, 0x30),
            ]
        );
        // A replacement shell after `exit` is not bring-up.
        evidence.observe(BringupRole::Shell, 2, 0x31);
        assert_eq!(drain(&mut evidence), []);
    }

    #[test]
    fn bringup_keeps_the_first_identity_and_ignores_zero() {
        let mut evidence = BringupEvidence::new();
        evidence.observe(BringupRole::Uart, 0, 0x10);
        evidence.observe(BringupRole::Uart, 1, 0);
        assert_eq!(evidence.next_due(), None);
        evidence.observe(BringupRole::Uart, 3, 0x13);
        evidence.observe(BringupRole::Uart, 4, 0x14);
        assert_eq!(
            evidence.next_due(),
            Some((crate::RoleId::Uart16550d, 3, 0x13))
        );
    }
}
