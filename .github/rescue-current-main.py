from pathlib import Path

path = Path("src/nr_conditional_handover.rs")
text = path.read_text()
start_marker = "    /// Advance time by `delta_ms` and evaluate all candidate condition state machines.\n"
end_marker = "    /// Autonomous execution of Conditional Handover / CPC to the selected candidate cell.\n"
start = text.index(start_marker)
end = text.index(end_marker, start)
new_block = '''    /// Advance time by `delta_ms` and evaluate all candidate condition state machines.
    /// Returns the strongest candidate whose Time-To-Trigger duration becomes satisfied,
    /// breaking equal-measurement ties by the lowest conditional reconfiguration ID.
    pub fn step_time(&mut self, delta_ms: u32) -> Option<u8> {
        let spcell_filtered = match self.spcell_filter.value() {
            Some(v) => v,
            None => return None,
        };

        let mut triggered_candidate: Option<(u8, f64)> = None;

        for candidate in self.candidates.values_mut() {
            // Check validity expiration
            candidate.elapsed_validity_ms = candidate.elapsed_validity_ms.saturating_add(delta_ms);
            if candidate.elapsed_validity_ms >= candidate.validity_timer_ms
                && matches!(
                    candidate.state,
                    CandidateState::Configured | CandidateState::TttActive { .. }
                )
            {
                candidate.state = CandidateState::Expired;
                self.metrics.expired_candidates += 1;
                continue;
            }

            // Only evaluate configured or active candidates
            match &mut candidate.state {
                CandidateState::Configured | CandidateState::TttActive { .. } => {}
                _ => continue,
            }

            let neighbor_filtered = match candidate.neighbor_filter.value() {
                Some(v) => v,
                None => continue,
            };

            self.metrics.candidate_evaluations += 1;

            if candidate
                .condition
                .evaluate_entering(spcell_filtered, neighbor_filtered)
            {
                let mut condition_became_met = false;
                match &mut candidate.state {
                    CandidateState::Configured => {
                        candidate.state = CandidateState::TttActive {
                            elapsed_ms: delta_ms,
                        };
                        self.metrics.ttt_activations += 1;
                        if delta_ms >= candidate.time_to_trigger_ms {
                            candidate.state = CandidateState::ConditionMet;
                            condition_became_met = true;
                        }
                    }
                    CandidateState::TttActive { elapsed_ms } => {
                        *elapsed_ms = elapsed_ms.saturating_add(delta_ms);
                        if *elapsed_ms >= candidate.time_to_trigger_ms {
                            candidate.state = CandidateState::ConditionMet;
                            condition_became_met = true;
                        }
                    }
                    _ => {}
                }

                if condition_became_met {
                    let cond_id = candidate.cond_reconfig_id;
                    let should_select = match triggered_candidate {
                        None => true,
                        Some((selected_id, selected_measurement)) => {
                            neighbor_filtered > selected_measurement
                                || (neighbor_filtered == selected_measurement && cond_id < selected_id)
                        }
                    };
                    if should_select {
                        triggered_candidate = Some((cond_id, neighbor_filtered));
                    }
                }
            } else if candidate
                .condition
                .evaluate_leaving(spcell_filtered, neighbor_filtered)
            {
                if matches!(candidate.state, CandidateState::TttActive { .. }) {
                    candidate.state = CandidateState::Configured;
                    self.metrics.ttt_resets += 1;
                }
            }
        }

        triggered_candidate.map(|(cond_id, _)| cond_id)
    }

'''
path.write_text(text[:start] + new_block + text[end:])
