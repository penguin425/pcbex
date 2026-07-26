use crate::{Board, Nm, Segment, checking, route_length_nm};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetQuality {
    pub net_id: u32,
    pub name: String,
    pub routed: bool,
    pub length_nm: Nm,
    pub segments: usize,
    pub arcs: usize,
    pub vias: usize,
    pub bends: usize,
    pub layers_used: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DifferentialQuality {
    pub name: String,
    pub positive_length_nm: Nm,
    pub negative_length_nm: Nm,
    pub skew_nm: Nm,
    pub coupled_percent: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingQuality {
    pub total_length_nm: Nm,
    pub total_vias: usize,
    pub total_bends: usize,
    pub routed_nets: usize,
    pub unrouted_nets: usize,
    pub nets: Vec<NetQuality>,
    pub differential_pairs: Vec<DifferentialQuality>,
}

impl RoutingQuality {
    pub fn regressions_against(&self, baseline: &Self) -> Vec<String> {
        let mut regressions = Vec::new();
        if self.total_length_nm > baseline.total_length_nm {
            regressions.push(format!(
                "total length regressed from {} to {} nm",
                baseline.total_length_nm, self.total_length_nm
            ));
        }
        if self.total_vias > baseline.total_vias {
            regressions.push(format!(
                "via count regressed from {} to {}",
                baseline.total_vias, self.total_vias
            ));
        }
        if self.total_bends > baseline.total_bends {
            regressions.push(format!(
                "bend count regressed from {} to {}",
                baseline.total_bends, self.total_bends
            ));
        }
        if self.unrouted_nets > baseline.unrouted_nets {
            regressions.push(format!(
                "unrouted-net count regressed from {} to {}",
                baseline.unrouted_nets, self.unrouted_nets
            ));
        }
        regressions
    }
}

pub fn routing_quality(board: &Board) -> RoutingQuality {
    let mut nets = Vec::new();
    for net in &board.nets {
        let route = board.routes.iter().find(|route| route.net_id == net.id);
        let bends = route.map_or(0, |route| {
            route
                .segments
                .windows(2)
                .filter(|pair| {
                    pair[0].end == pair[1].start
                        && segment_direction(&pair[0]) != segment_direction(&pair[1])
                })
                .count()
        });
        let layers_used = route.map_or(0, |route| {
            route
                .segments
                .iter()
                .map(|segment| segment.layer)
                .collect::<HashSet<_>>()
                .len()
        });
        nets.push(NetQuality {
            net_id: net.id,
            name: net.name.clone(),
            routed: route.is_some(),
            length_nm: route.map_or(0, route_length_nm),
            segments: route.map_or(0, |route| route.segments.len()),
            arcs: route.map_or(0, |route| route.arcs.len()),
            vias: route.map_or(0, |route| route.vias.len()),
            bends,
            layers_used,
        });
    }
    let differential_pairs = board
        .differential_pairs
        .iter()
        .filter_map(|pair| {
            let positive = board
                .routes
                .iter()
                .find(|route| route.net_id == pair.positive_net_id)?;
            let negative = board
                .routes
                .iter()
                .find(|route| route.net_id == pair.negative_net_id)?;
            let positive_length_nm = route_length_nm(positive);
            let negative_length_nm = route_length_nm(negative);
            Some(DifferentialQuality {
                name: pair.name.clone(),
                positive_length_nm,
                negative_length_nm,
                skew_nm: (positive_length_nm - negative_length_nm).abs(),
                coupled_percent: checking::coupled_percent(positive, negative, pair)
                    .min(checking::coupled_percent(negative, positive, pair)),
            })
        })
        .collect();
    RoutingQuality {
        total_length_nm: nets.iter().map(|net| net.length_nm).sum(),
        total_vias: nets.iter().map(|net| net.vias).sum(),
        total_bends: nets.iter().map(|net| net.bends).sum(),
        routed_nets: nets.iter().filter(|net| net.routed).count(),
        unrouted_nets: nets.iter().filter(|net| !net.routed).count(),
        nets,
        differential_pairs,
    }
}

fn segment_direction(segment: &Segment) -> (i64, i64) {
    (
        (segment.end.x_nm - segment.start.x_nm).signum(),
        (segment.end.y_nm - segment.start.y_nm).signum(),
    )
}
