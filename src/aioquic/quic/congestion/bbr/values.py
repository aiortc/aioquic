from ..congestion import K_MAX_DATAGRAM_SIZE, K_MINIMUM_WINDOW, K_INITIAL_WINDOW, Now
from enum import Enum
from dataclasses import dataclass
from typing import Optional
from ..minmax import Minmax

# A constant specifying the length of the BBR.BtlBw max filter window for
# BBR.BtlBwFilter, BtlBwFilterLen is 10 packet-timed round trips.
BTLBW_FILTER_LEN: float = 10

# A constant specifying the minimum time interval between ProbeRTT states: 10
# secs.
PROBE_RTT_INTERVAL: float = 10

# A constant specifying the length of the RTProp min filter window.
RTPROP_FILTER_LEN: float = PROBE_RTT_INTERVAL

# A constant specifying the minimum gain value that will allow the sending
# rate to double each round (2/ln(2) ~= 2.89), used in Startup mode for both
# BBR.pacing_gain and BBR.cwnd_gain.
BBR_HIGH_GAIN: float = 2.89

# The minimal cwnd value BBR tries to target using: 4 packets, or 4 * SMSS
BBR_MIN_PIPE_CWND_PKTS: int = 4

# The number of phases in the BBR ProbeBW gain cycle: 8.
BBR_GAIN_CYCLE_LEN: int = 8

# A constant specifying the minimum duration for which ProbeRTT state holds
# inflight to BBRMinPipeCwnd or fewer packets: 200 ms.
PROBE_RTT_DURATION: float = 0.200

# Pacing Gain Cycle.
PACING_GAIN_CYCLE: list[float] = [5.0 / 4.0, 3.0 / 4.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]

# A constant to check BBR.BtlBW is still growing.
BTLBW_GROWTH_TARGET: float = 1.25

# Some unatteignable value representing MaxInt
MAX_INT = 10e64  

# The minimum time added to the rtt to spend in each pacing cycle
K_BBR_MIN_CYCLE_DURATION : float = 0

class BBRState(Enum):
    Startup=0
    Drain=1
    ProbeBW=2
    ProbeRTT=3
    
class BBRACKPhase(Enum):
    Init=0
    ProbeFeedback=1
    ProbeStarting=2
    ProbeStopping=3
    Refilling=4
    

@dataclass
class BBR:

    # The current state of a BBR flow in the BBR state machine.
    state: BBRState = BBRState.Startup

    # The current pacing rate for a BBR flow, which controls inter-packet
    # spacing.
    pacing_rate: int = 0

    # BBR's estimated bottleneck bandwidth available to the transport flow,
    # estimated from the maximum delivery rate sample in a sliding window.
    btlbw: int = 0

    # The max filter used to estimate BBR.BtlBw.
    btlbwfilter: Minmax = Minmax(0)

    # BBR's estimated two-way round-trip propagation delay of the path,
    # estimated from the windowed minimum recent round-trip delay sample.
    rtprop: float = 0

    # The wall clock time at which the current BBR.RTProp sample was obtained.
    rtprop_stamp: float = 0

    # A boolean recording whether the BBR.RTprop has expired and is due for a
    # refresh with an application idle period or a transition into ProbeRTT
    # state.
    rtprop_expired: bool = False

    # The dynamic gain factor used to scale BBR.BtlBw to produce
    # BBR.pacing_rate.
    pacing_gain: float = 0.0

    # The dynamic gain factor used to scale the estimated BDP to produce a
    # congestion window (cwnd).
    cwnd_gain: float = 0.0

    # A boolean that records whether BBR estimates that it has ever fully
    # utilized its available bandwidth ("filled the pipe").
    filled_pipe: bool = False

    # Count of packet-timed round trips elapsed so far.
    round_count: int = 0

    # A boolean that BBR sets to true once per packet-timed round trip,
    # on ACKs that advance BBR.round_count.
    round_start: bool = False

    # packet.delivered value denoting the end of a packet-timed round trip.
    next_round_delivered: int = 0

    # Timestamp when ProbeRTT state ends.
    probe_rtt_done_stamp: float = None

    # Checking if a roundtrip in ProbeRTT state ends.
    probe_rtt_round_done: bool = False

    # Checking if in the packet conservation mode during recovery.
    packet_conservation: bool = False

    # Saved cwnd before loss recovery.
    prior_cwnd: int = 0

    # Checking if restarting from idle.
    idle_restart: bool = False

    # Baseline level delivery rate for full pipe estimator.
    full_bw: int = 0

    # The number of round for full pipe estimator without much growth.
    full_bw_count: int = 0

    # Last time cycle_index is updated.
    cycle_stamp: float = 0

    # Current index of pacing_gain_cycle[].
    cycle_index: int = 0

    # The upper bound on the volume of data BBR allows in flight.
    target_cwnd: int = 0

    # Whether in the recovery episode.
    in_recovery: bool = False

    # Start time of the connection.
    start_time: float = 0

    # Newly marked lost data size in bytes.
    newly_lost_bytes: int = 0

    # Newly acked data size in bytes.
    newly_acked_bytes: int = 0

    # bytes_in_flight before processing this ACK.
    prior_bytes_in_flight: int = 0
 
    # the congestion window used by the recovery
    cwnd : int = K_INITIAL_WINDOW