"""
PCAP Parser Service — basic network analysis using Scapy.

Provides:
- Parse PCAP files and extract flow-like metadata
- Extract source/destination IP, ports, protocols
- Convert parsed PCAP data into a DataFrame compatible with the ML pipeline

Scope: Basic Scapy parsing for academic prototype (as per project specification).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

logger = logging.getLogger(__name__)


def parse_pcap(file_path: str | Path) -> pd.DataFrame:
    """
    Parse a PCAP file using Scapy and extract network flow metadata.
    
    Returns a DataFrame with columns matching the simplified ML pipeline input.
    For full CICIDS2017-style flow features, use CICFlowMeter externally.
    This provides basic packet-level extraction for demonstration.
    
    Returns:
        DataFrame with columns:
        - Source IP, Destination IP
        - Source Port, Destination Port
        - Protocol (TCP=6, UDP=17, ICMP=1)
        - Packet Length, Timestamp
        - TCP Flags (if TCP)
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    except ImportError:
        logger.error("Scapy not installed. Install with: pip install scapy")
        raise ImportError("Scapy is required for PCAP parsing")

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    logger.info(f"Parsing PCAP file: {file_path}")
    packets = rdpcap(str(file_path))
    logger.info(f"Read {len(packets)} packets")

    records: List[Dict[str, Any]] = []
    for i, pkt in enumerate(packets):
        if not pkt.haslayer(IP):
            continue

        ip_layer = pkt[IP]
        record: Dict[str, Any] = {
            " Source IP": ip_layer.src,
            " Destination IP": ip_layer.dst,
            " Protocol": ip_layer.proto,
            "packet_length": len(pkt),
            "timestamp": float(pkt.time),
        }

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            record[" Source Port"] = tcp.sport
            record[" Destination Port"] = tcp.dport
            record["tcp_flags"] = str(tcp.flags)
            record[" SYN Flag Count"] = 1 if "S" in str(tcp.flags) else 0
            record[" FIN Flag Count"] = 1 if "F" in str(tcp.flags) else 0
            record[" RST Flag Count"] = 1 if "R" in str(tcp.flags) else 0
            record[" ACK Flag Count"] = 1 if "A" in str(tcp.flags) else 0
            record[" Fwd PSH Flags"] = 1 if "P" in str(tcp.flags) else 0
            record[" Fwd URG Flags"] = 1 if "U" in str(tcp.flags) else 0
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            record[" Source Port"] = udp.sport
            record[" Destination Port"] = udp.dport
            record["tcp_flags"] = ""
            record[" SYN Flag Count"] = 0
            record[" FIN Flag Count"] = 0
            record[" RST Flag Count"] = 0
            record[" ACK Flag Count"] = 0
            record[" Fwd PSH Flags"] = 0
            record[" Fwd URG Flags"] = 0
        else:
            record[" Source Port"] = 0
            record[" Destination Port"] = 0
            record["tcp_flags"] = ""
            record[" SYN Flag Count"] = 0
            record[" FIN Flag Count"] = 0
            record[" RST Flag Count"] = 0
            record[" ACK Flag Count"] = 0
            record[" Fwd PSH Flags"] = 0
            record[" Fwd URG Flags"] = 0

        records.append(record)

    df = pd.DataFrame(records)
    logger.info(f"Extracted {len(df)} IP packets from PCAP")

    # Compute basic flow-like features from packet-level data
    if len(df) > 0:
        df = _compute_basic_flow_features(df)

    return df


def _compute_basic_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute basic flow-like features from packet-level data.
    
    Groups by (src_ip, dst_ip, src_port, dst_port, protocol) to create
    pseudo-flow records. Adds basic statistics that approximate CICIDS2017 features.
    """
    # Group by flow tuple
    flow_key = [" Source IP", " Destination IP", " Source Port", " Destination Port", " Protocol"]

    # For each flow, compute aggregated features
    flows = []
    for key, group in df.groupby(flow_key, sort=False):
        src_ip, dst_ip, src_port, dst_port, protocol = key
        pkt_lengths = group["packet_length"].values

        flow = {
            "Flow ID": f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}",
            " Source IP": src_ip,
            " Destination IP": dst_ip,
            " Source Port": src_port,
            " Destination Port": dst_port,
            " Protocol": protocol,
            " Timestamp": datetime.fromtimestamp(
                group["timestamp"].iloc[0], tz=timezone.utc
            ).strftime("%d/%m/%Y %H:%M:%S"),

            # Flow duration (microseconds)
            " Flow Duration": int(
                (group["timestamp"].max() - group["timestamp"].min()) * 1e6
            ),

            # Packet counts (simplified: all as forward)
            " Total Fwd Packets": len(group),
            " Total Backward Packets": 0,

            # Lengths
            "Total Length of Fwd Packets": int(pkt_lengths.sum()),
            " Total Length of Bwd Packets": 0,
            " Fwd Packet Length Max": int(pkt_lengths.max()),
            " Fwd Packet Length Mean": round(float(pkt_lengths.mean()), 2),
            " Bwd Packet Length Max": 0,
            " Bwd Packet Length Mean": 0,

            # Rates
            " Flow Bytes/s": round(float(
                pkt_lengths.sum() / max(
                    group["timestamp"].max() - group["timestamp"].min(), 0.001
                )
            ), 2),
            " Flow Packets/s": round(float(
                len(group) / max(
                    group["timestamp"].max() - group["timestamp"].min(), 0.001
                )
            ), 2),

            # IAT (inter-arrival time) - basic
            " Flow IAT Mean": round(float(
                group["timestamp"].diff().mean() * 1e6
            ), 2) if len(group) > 1 else 0,
            " Flow IAT Std": round(float(
                group["timestamp"].diff().std() * 1e6
            ), 2) if len(group) > 2 else 0,
            " Fwd IAT Total": int(
                (group["timestamp"].max() - group["timestamp"].min()) * 1e6
            ),
            " Bwd IAT Total": 0,

            # Flags (aggregate)
            " SYN Flag Count": int(group[" SYN Flag Count"].sum()),
            " FIN Flag Count": int(group[" FIN Flag Count"].sum()),
            " RST Flag Count": int(group[" RST Flag Count"].sum()),
            " ACK Flag Count": int(group[" ACK Flag Count"].sum()),
            " Fwd PSH Flags": int(group[" Fwd PSH Flags"].sum()),
            " Fwd URG Flags": int(group[" Fwd URG Flags"].sum()),

            # Additional features set to basic defaults
            "Fwd Packets/s": round(float(
                len(group) / max(
                    group["timestamp"].max() - group["timestamp"].min(), 0.001
                )
            ), 2),
            " Bwd Packets/s": 0,
            " Min Packet Length": int(pkt_lengths.min()),
            " Max Packet Length": int(pkt_lengths.max()),
            " Packet Length Mean": round(float(pkt_lengths.mean()), 2),
            " Packet Length Std": round(float(pkt_lengths.std()), 2) if len(pkt_lengths) > 1 else 0,
            " Packet Length Variance": round(float(pkt_lengths.var()), 2) if len(pkt_lengths) > 1 else 0,
            " Down/Up Ratio": 0,
            " Average Packet Size": round(float(pkt_lengths.mean()), 2),
            " Avg Fwd Segment Size": round(float(pkt_lengths.mean()), 2),
            " Avg Bwd Segment Size": 0,
            "Init_Win_bytes_forward": 0,
            " Init_Win_bytes_backward": 0,
            " Active Mean": 0,
            " Idle Mean": 0,

            # No label for uploaded PCAPs — model will classify
            " Label": "UNKNOWN",
        }
        flows.append(flow)

    result = pd.DataFrame(flows)
    logger.info(f"Aggregated into {len(result)} pseudo-flows from {len(df)} packets")
    return result


def get_pcap_summary(file_path: str | Path) -> Dict[str, Any]:
    """
    Get a quick summary of a PCAP file without full processing.
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        return {"error": "Scapy not installed"}

    file_path = Path(file_path)
    if not file_path.exists():
        return {"error": f"File not found: {file_path}"}

    packets = rdpcap(str(file_path))

    ip_count = sum(1 for p in packets if p.haslayer(IP))
    tcp_count = sum(1 for p in packets if p.haslayer(TCP))
    udp_count = sum(1 for p in packets if p.haslayer(UDP))

    src_ips = set()
    dst_ips = set()
    for pkt in packets:
        if pkt.haslayer(IP):
            src_ips.add(pkt[IP].src)
            dst_ips.add(pkt[IP].dst)

    return {
        "total_packets": len(packets),
        "ip_packets": ip_count,
        "tcp_packets": tcp_count,
        "udp_packets": udp_count,
        "unique_sources": len(src_ips),
        "unique_destinations": len(dst_ips),
        "file_size_bytes": file_path.stat().st_size,
    }
