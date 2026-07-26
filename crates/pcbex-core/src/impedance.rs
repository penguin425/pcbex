use crate::{
    Board, Layer, Nm, Route, estimated_stackup_differential_impedance_ohms,
    estimated_stackup_impedance_ohms,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ImpedanceReport {
    pub nets: Vec<NetImpedanceReport>,
    pub differential_pairs: Vec<DifferentialImpedanceReport>,
    pub invalid_geometry_count: usize,
    pub out_of_tolerance_segment_count: usize,
    pub excessive_transition_count: usize,
}

impl ImpedanceReport {
    pub fn is_clean(&self) -> bool {
        self.invalid_geometry_count == 0
            && self.out_of_tolerance_segment_count == 0
            && self.excessive_transition_count == 0
    }

    pub fn regressions_against(&self, baseline: &Self) -> Vec<String> {
        let mut regressions = Vec::new();
        for (name, current, previous) in [
            (
                "invalid geometry count",
                self.invalid_geometry_count,
                baseline.invalid_geometry_count,
            ),
            (
                "out-of-tolerance segment count",
                self.out_of_tolerance_segment_count,
                baseline.out_of_tolerance_segment_count,
            ),
            (
                "excessive transition count",
                self.excessive_transition_count,
                baseline.excessive_transition_count,
            ),
        ] {
            if current > previous {
                regressions.push(format!("{name} increased from {previous} to {current}"));
            }
        }
        for net in &self.nets {
            let Some(previous) = baseline.nets.iter().find(|item| item.net_id == net.net_id) else {
                continue;
            };
            compare_step(
                &format!("net {}", net.name),
                net.maximum_observed_step_ohms,
                previous.maximum_observed_step_ohms,
                &mut regressions,
            );
            compare_segments(
                &format!("net {}", net.name),
                &net.segments,
                &previous.segments,
                &mut regressions,
            );
        }
        for pair in &self.differential_pairs {
            let Some(previous_pair) = baseline
                .differential_pairs
                .iter()
                .find(|item| item.name == pair.name)
            else {
                continue;
            };
            for member in &pair.members {
                let Some(previous) = previous_pair
                    .members
                    .iter()
                    .find(|item| item.net_id == member.net_id)
                else {
                    continue;
                };
                let label = format!("differential pair {} net {}", pair.name, member.net_id);
                compare_step(
                    &label,
                    member.maximum_observed_step_ohms,
                    previous.maximum_observed_step_ohms,
                    &mut regressions,
                );
                compare_segments(
                    &label,
                    &member.segments,
                    &previous.segments,
                    &mut regressions,
                );
            }
        }
        regressions
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetImpedanceReport {
    pub net_id: u32,
    pub name: String,
    pub class_name: Option<String>,
    pub target_ohms: Option<f64>,
    pub tolerance_ohms: Option<f64>,
    pub maximum_allowed_step_ohms: Option<f64>,
    pub maximum_observed_step_ohms: Option<f64>,
    pub segments: Vec<SegmentImpedanceReport>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DifferentialImpedanceReport {
    pub name: String,
    pub positive_net_id: u32,
    pub negative_net_id: u32,
    pub gap_nm: Nm,
    pub target_ohms: Option<f64>,
    pub tolerance_ohms: Option<f64>,
    pub maximum_allowed_step_ohms: Option<f64>,
    pub members: Vec<DifferentialMemberImpedanceReport>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DifferentialMemberImpedanceReport {
    pub net_id: u32,
    pub maximum_observed_step_ohms: Option<f64>,
    pub segments: Vec<SegmentImpedanceReport>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SegmentImpedanceReport {
    pub index: usize,
    pub layer: Layer,
    pub width_nm: Nm,
    pub estimated_ohms: Option<f64>,
    pub deviation_ohms: Option<f64>,
    pub within_target: Option<bool>,
}

fn compare_step(
    label: &str,
    current: Option<f64>,
    previous: Option<f64>,
    regressions: &mut Vec<String>,
) {
    if let (Some(current), Some(previous)) = (current, previous)
        && current > previous + f64::EPSILON
    {
        regressions.push(format!(
            "{label} maximum transition step increased from {previous:.2} to {current:.2} Ω"
        ));
    }
}

fn compare_segments(
    label: &str,
    current: &[SegmentImpedanceReport],
    previous: &[SegmentImpedanceReport],
    regressions: &mut Vec<String>,
) {
    for segment in current {
        let Some(previous) = previous.iter().find(|item| item.index == segment.index) else {
            continue;
        };
        if let (Some(current), Some(previous)) = (segment.deviation_ohms, previous.deviation_ohms)
            && current.abs() > previous.abs() + f64::EPSILON
        {
            regressions.push(format!(
                "{label} segment {} target deviation increased from {:.2} to {:.2} Ω",
                segment.index,
                previous.abs(),
                current.abs()
            ));
        }
    }
}

pub fn impedance_report(board: &Board) -> ImpedanceReport {
    let routes: HashMap<_, _> = board
        .routes
        .iter()
        .map(|route| (route.net_id, route))
        .collect();
    let paired_net_ids: HashSet<_> = board
        .differential_pairs
        .iter()
        .flat_map(|pair| [pair.positive_net_id, pair.negative_net_id])
        .collect();
    let mut invalid_geometry_count = 0;
    let mut nets = Vec::new();
    for net in &board.nets {
        if paired_net_ids.contains(&net.id) {
            continue;
        }
        let Some(route) = routes.get(&net.id) else {
            continue;
        };
        let class = net
            .class
            .as_ref()
            .and_then(|name| board.net_classes.get(name));
        let target = class.and_then(|rules| rules.target_impedance_ohms);
        let tolerance = class.and_then(|rules| rules.impedance_tolerance_ohms);
        let estimates = route
            .segments
            .iter()
            .map(|segment| {
                board
                    .stackup
                    .iter()
                    .find(|entry| entry.layer == segment.layer)
                    .and_then(|stackup| estimated_stackup_impedance_ohms(segment.width_nm, stackup))
            })
            .collect::<Vec<_>>();
        invalid_geometry_count += estimates.iter().filter(|value| value.is_none()).count();
        nets.push(NetImpedanceReport {
            net_id: net.id,
            name: net.name.clone(),
            class_name: net.class.clone(),
            target_ohms: target,
            tolerance_ohms: tolerance,
            maximum_allowed_step_ohms: class.and_then(|rules| rules.maximum_impedance_step_ohms),
            maximum_observed_step_ohms: maximum_transition_step(route, &estimates),
            segments: segment_reports(route, &estimates, target, tolerance),
        });
    }

    let mut differential_pairs = Vec::new();
    for pair in &board.differential_pairs {
        let mut members = Vec::new();
        for net_id in [pair.positive_net_id, pair.negative_net_id] {
            let Some(route) = routes.get(&net_id) else {
                continue;
            };
            let estimates = route
                .segments
                .iter()
                .map(|segment| {
                    board
                        .stackup
                        .iter()
                        .find(|entry| entry.layer == segment.layer)
                        .and_then(|stackup| {
                            estimated_stackup_differential_impedance_ohms(
                                segment.width_nm,
                                pair.gap_nm,
                                stackup,
                            )
                        })
                })
                .collect::<Vec<_>>();
            invalid_geometry_count += estimates.iter().filter(|value| value.is_none()).count();
            members.push(DifferentialMemberImpedanceReport {
                net_id,
                maximum_observed_step_ohms: maximum_transition_step(route, &estimates),
                segments: segment_reports(
                    route,
                    &estimates,
                    pair.target_differential_impedance_ohms,
                    pair.differential_impedance_tolerance_ohms,
                ),
            });
        }
        differential_pairs.push(DifferentialImpedanceReport {
            name: pair.name.clone(),
            positive_net_id: pair.positive_net_id,
            negative_net_id: pair.negative_net_id,
            gap_nm: pair.gap_nm,
            target_ohms: pair.target_differential_impedance_ohms,
            tolerance_ohms: pair.differential_impedance_tolerance_ohms,
            maximum_allowed_step_ohms: pair.maximum_differential_impedance_step_ohms,
            members,
        });
    }
    let out_of_tolerance_segment_count = nets
        .iter()
        .flat_map(|net| &net.segments)
        .chain(
            differential_pairs
                .iter()
                .flat_map(|pair| &pair.members)
                .flat_map(|member| &member.segments),
        )
        .filter(|segment| segment.within_target == Some(false))
        .count();
    let excessive_transition_count = nets
        .iter()
        .filter(|net| {
            matches!(
                (
                    net.maximum_observed_step_ohms,
                    net.maximum_allowed_step_ohms
                ),
                (Some(observed), Some(allowed)) if observed > allowed
            )
        })
        .count()
        + differential_pairs
            .iter()
            .flat_map(|pair| {
                pair.members.iter().map(move |member| {
                    (
                        member.maximum_observed_step_ohms,
                        pair.maximum_allowed_step_ohms,
                    )
                })
            })
            .filter(|(observed, allowed)| {
                matches!((observed, allowed), (Some(observed), Some(allowed)) if observed > allowed)
            })
            .count();
    ImpedanceReport {
        nets,
        differential_pairs,
        invalid_geometry_count,
        out_of_tolerance_segment_count,
        excessive_transition_count,
    }
}

fn segment_reports(
    route: &Route,
    estimates: &[Option<f64>],
    target: Option<f64>,
    tolerance: Option<f64>,
) -> Vec<SegmentImpedanceReport> {
    route
        .segments
        .iter()
        .zip(estimates)
        .enumerate()
        .map(|(index, (segment, estimated))| {
            let deviation = estimated.zip(target).map(|(value, target)| value - target);
            SegmentImpedanceReport {
                index,
                layer: segment.layer,
                width_nm: segment.width_nm,
                estimated_ohms: *estimated,
                deviation_ohms: deviation,
                within_target: deviation
                    .zip(tolerance)
                    .map(|(deviation, tolerance)| deviation.abs() <= tolerance),
            }
        })
        .collect()
}

fn maximum_transition_step(route: &Route, estimates: &[Option<f64>]) -> Option<f64> {
    let mut maximum = None::<f64>;
    for via in &route.vias {
        let connected = route
            .segments
            .iter()
            .zip(estimates)
            .filter(|(segment, _)| {
                (segment.start == via.position || segment.end == via.position)
                    && via.spans_layer(segment.layer)
            })
            .filter_map(|(_, estimate)| *estimate)
            .collect::<Vec<_>>();
        if connected.len() < 2 {
            continue;
        }
        let low = connected.iter().copied().fold(f64::INFINITY, f64::min);
        let high = connected.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        maximum = Some(maximum.map_or(high - low, |current| current.max(high - low)));
    }
    maximum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_state_includes_every_gate_counter() {
        let mut report = ImpedanceReport {
            nets: vec![],
            differential_pairs: vec![],
            invalid_geometry_count: 0,
            out_of_tolerance_segment_count: 0,
            excessive_transition_count: 0,
        };
        assert!(report.is_clean());
        report.excessive_transition_count = 1;
        assert!(!report.is_clean());
    }

    #[test]
    fn baseline_comparison_detects_count_and_segment_regressions() {
        let segment = SegmentImpedanceReport {
            index: 0,
            layer: Layer::Front,
            width_nm: 250_000,
            estimated_ohms: Some(50.0),
            deviation_ohms: Some(0.5),
            within_target: Some(true),
        };
        let mut baseline = ImpedanceReport {
            nets: vec![NetImpedanceReport {
                net_id: 1,
                name: "CLK".into(),
                class_name: Some("Controlled".into()),
                target_ohms: Some(50.0),
                tolerance_ohms: Some(2.0),
                maximum_allowed_step_ohms: Some(3.0),
                maximum_observed_step_ohms: Some(1.0),
                segments: vec![segment],
            }],
            differential_pairs: vec![],
            invalid_geometry_count: 0,
            out_of_tolerance_segment_count: 0,
            excessive_transition_count: 0,
        };
        let mut current = baseline.clone();
        current.invalid_geometry_count = 1;
        current.nets[0].segments[0].deviation_ohms = Some(1.5);
        current.nets[0].maximum_observed_step_ohms = Some(2.0);

        let regressions = current.regressions_against(&baseline);
        assert_eq!(regressions.len(), 3);
        baseline.invalid_geometry_count = 2;
        assert!(
            current
                .regressions_against(&baseline)
                .iter()
                .all(|message| !message.contains("invalid geometry count"))
        );
    }
}
