"""
NetFlow request schema.

Represents a single raw NetFlow v9 / IPFIX record as submitted by the caller.
All fields default to 0 so callers can send only the fields they have.
"""

from pydantic import BaseModel, Field


class NetFlowRecord(BaseModel):
    """
    A single raw NetFlow v9/IPFIX record.
    Field names match the NF-UNSW-NB15-v3 dataset columns exactly.
    Extra fields are accepted and forwarded to the pipeline unchanged.
    """

    model_config = {"extra": "allow"}

    # Core flow fields
    L4_DST_PORT: int                = Field(0,   description="Destination port")
    L4_SRC_PORT: int                = Field(0,   description="Source port")
    IN_BYTES: int                   = Field(0,   description="Inbound bytes")
    OUT_BYTES: int                  = Field(0,   description="Outbound bytes")
    IN_PKTS: int                    = Field(0,   description="Inbound packets")
    OUT_PKTS: int                   = Field(0,   description="Outbound packets")
    FLOW_DURATION_MILLISECONDS: int = Field(0,   description="Flow duration (ms)")
    PROTOCOL: int                   = Field(6,   description="IP protocol (6=TCP)")
    TCP_FLAGS: int                  = Field(0,   description="TCP flags bitmask")

    # TTL
    MIN_TTL: int                    = Field(0)
    MAX_TTL: int                    = Field(0)

    # Packet sizes
    SHORTEST_FLOW_PKT: int          = Field(0)
    LONGEST_FLOW_PKT: int           = Field(0)
    MIN_IP_PKT_LEN: int             = Field(0)
    MAX_IP_PKT_LEN: int             = Field(0)

    # Throughput
    SRC_TO_DST_SECOND_BYTES: float  = Field(0.0)
    DST_TO_SRC_SECOND_BYTES: float  = Field(0.0)
    SRC_TO_DST_AVG_THROUGHPUT: int  = Field(0)
    DST_TO_SRC_AVG_THROUGHPUT: int  = Field(0)

    # Retransmissions
    RETRANSMITTED_IN_BYTES: int     = Field(0)
    RETRANSMITTED_IN_PKTS: int      = Field(0)
    RETRANSMITTED_OUT_BYTES: int    = Field(0)
    RETRANSMITTED_OUT_PKTS: int     = Field(0)

    # Packet-size distribution buckets
    NUM_PKTS_UP_TO_128_BYTES: int   = Field(0)
    NUM_PKTS_128_TO_256_BYTES: int  = Field(0)
    NUM_PKTS_256_TO_512_BYTES: int  = Field(0)
    NUM_PKTS_512_TO_1024_BYTES: int = Field(0)
    NUM_PKTS_1024_TO_1514_BYTES: int = Field(0)

    # TCP window
    TCP_WIN_MAX_IN: int             = Field(0)
    TCP_WIN_MAX_OUT: int            = Field(0)

    # Duration split
    DURATION_IN: int                = Field(0)
    DURATION_OUT: int               = Field(0)

    # Inter-arrival times (src→dst)
    SRC_TO_DST_IAT_MIN: int         = Field(0)
    SRC_TO_DST_IAT_MAX: int         = Field(0)
    SRC_TO_DST_IAT_AVG: int         = Field(0)
    SRC_TO_DST_IAT_STDDEV: int      = Field(0)

    # Inter-arrival times (dst→src)
    DST_TO_SRC_IAT_MIN: int         = Field(0)
    DST_TO_SRC_IAT_MAX: int         = Field(0)
    DST_TO_SRC_IAT_AVG: int         = Field(0)
    DST_TO_SRC_IAT_STDDEV: int      = Field(0)

    # TCP flags split
    SERVER_TCP_FLAGS: int           = Field(0)
    CLIENT_TCP_FLAGS: int           = Field(0)
