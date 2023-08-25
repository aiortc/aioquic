from ..congestion import K_MAX_DATAGRAM_SIZE, K_MINIMUM_WINDOW, K_INITIAL_WINDOW, Now
from enum import Enum
from dataclasses import dataclass
from typing import Optional
from .minmax import Minmax

# The static discount factor of 1% used to scale BBR.bw to produce
# BBR.pacing_rate.
K_BBR2_PACING_MARGIN_PERCENT = 0.01

# A constant specifying the minimum gain value
# for calculating the pacing rate that will allow the sending rate to
# double each round (4*ln(2) ~=2.77 ) [BBRStartupPacingGain] used in
# Startup mode for BBR.pacing_gain.
K_BBR2_STARTUP_PACING_GAIN = 2.77

# A constant specifying the pacing gain value for Probe Down mode.
K_BBR2_PROBE_DOWN_PACING_GAIN = 3/4

# A constant specifying the pacing gain value for Probe Up mode.
K_BBR2_PROBE_UP_PACING_GAIN = 5/4

# A constant specifying the pacing gain value for Probe Refill, Probe RTT,
# Cruise mode.
K_BBR2_PACING_GAIN = 1.0

# A constant specifying the minimum gain value for the cwnd in the Startup
# phase
K_BBR2_STARTUP_CWND_GAIN = 2.77

# A constant specifying the minimum gain value for
# calculating the cwnd that will allow the sending rate to double each
# round (2.0) used in Probe and Drain mode for BBR.cwnd_gain.
K_BBR2_CWND_GAIN = 2.0

# The maximum tolerated per-round-trip packet loss rate
# when probing for bandwidth (the default is 2%).
K_BBR2_LOSS_THRESH = 0.02

# Exit startup if the number of loss marking events is >=FULL_LOSS_COUNT
K_BBR2_FULL_LOSS_COUNT = 8

# The default multiplicative decrease to make upon each round
# trip during which the connection detects packet loss (the value is
# 0.7).
K_BBR2_BETA = 0.7

# The multiplicative factor to apply to BBR.inflight_hi
# when attempting to leave free headroom in the path (e.g. free space
# in the bottleneck buffer or free time slots in the bottleneck link)
# that can be used by cross traffic (the value is 0.85).
K_BBR2_HEADROOM = 0.85

# The minimal cwnd value BBR targets, to allow
# pipelining with TCP endpoints that follow an "ACK every other packet"
# delayed-ACK policy: 4 * SMSS.
K_BBR2_MIN_PIPE_CWND_PKTS = 4

# To do: Tune window for expiry of Max BW measurement
# The filter window length for BBR.MaxBwFilter = 2 (representing up to 2
# ProbeBW cycles, the current cycle and the previous full cycle).
# K_BBR2_MAX_BW_FILTER_LEN: Duration = Duration::from_secs(2)

# To do: Tune window for expiry of ACK aggregation measurement
# The window length of the BBR.ExtraACKedFilter max filter window: 10 (in
# units of packet-timed round trips).
# K_BBR2_EXTRA_ACKED_FILTER_LEN: Duration = Duration::from_secs(10)

# A constant specifying the length of the BBR.min_rtt min filter window,
# MinRTTFilterLen is 10 secs.
K_BBR2_MIN_RTT_FILTER_LEN = 1

# A constant specifying the gain value for calculating the cwnd during
# ProbeRTT: 0.5 (meaning that ProbeRTT attempts to reduce in-flight data to
# 50% of the estimated BDP).
K_BBR2_PROBE_RTT_CWND_GAIN = 0.5

# A constant specifying the minimum duration for which ProbeRTT state holds
# inflight to BBRMinPipeCwnd or fewer packets: 200 ms.
K_BBR2_PROBE_RTT_DURATION = 0.2 # in seconds

# ProbeRTTInterval: A constant specifying the minimum time interval between
# ProbeRTT states. To do: investigate probe duration. Set arbirarily high for
# now.
K_BBR2_PROBE_RTT_INTERVAL = 86400

# Threshold for checking a full bandwidth growth during Startup.
K_BBR2_MAX_BW_GROWTH_THRESHOLD = 1.25

# Threshold for determining maximum bandwidth of network during Startup.
K_BBR2_MAX_BW_COUNT = 3

# Some unatteignable value representing MaxInt
MAX_INT = 10e64  

class BBR2State(Enum):
    Startup=0
    Drain=1
    ProbeBWDOWN=2
    ProbeBWCRUISE=3
    ProbeBWREFILL=4
    ProbeBWUP=5
    ProbeRTT=6
    
class BBR2ACKPhase(Enum):
    INIT=0
    ACKS_PROBE_FEEDBACK=1
    ACKS_PROBE_STARTING=2
    ACKS_PROBE_STOPPING=3
    ACKS_REFILLING=4
    

@dataclass
class BBR2:
    #2.3.  Per-ACK Rate Sample State
    #It's stored in rate sample but we keep in BBR state here.

    #The volume of data that was estimated to be in
    #flight at the time of the transmission of the packet that has just
    #been ACKed.
    tx_in_flight: int = 0

    #The volume of data that was declared lost between the
    #transmission and acknowledgement of the packet that has just been
    #ACKed.
    lost: int = 0

    #The volume of data cumulatively or selectively acknowledged upon the ACK
    #that was just received.  (This quantity is referred to as "DeliveredData"
    #in [RFC6937].)
    newly_acked_bytes: int = 0

    #The volume of data newly marked lost upon the ACK that was just received.
    newly_lost_bytes: int = 0

    #2.4.  Output Control Parameters
    #The current pacing rate for a BBR2 flow, which controls inter-packet
    #spacing.
    pacing_rate: int = 0

    #Save initial pacing rate so we can update when more reliable bytes
    #delivered and RTT samples are available
    init_pacing_rate: int = 0

    #2.5.  Pacing State and Parameters
    #The dynamic gain factor used to scale BBR.bw to
    #produce BBR.pacing_rate.
    pacing_gain: float = 0.0

    #2.6.  cwnd State and Parameters
    #The dynamic gain factor used to scale the estimated BDP to produce a
    #congestion window (cwnd).
    cwnd_gain: float = 0.0

    #A boolean indicating whether BBR is currently using packet conservation
    #dynamics to bound cwnd.
    packet_conservation: bool = False

    #2.7.  General Algorithm State
    #The current state of a BBR2 flow in the BBR2 state machine.
    state: BBR2State = BBR2State.Startup

    #Count of packet-timed round trips elapsed so far.
    round_count: int  = 0

    #A boolean that BBR2 sets to true once per packet-timed round trip,
    #on ACKs that advance BBR2.round_count.
    round_start: bool = False

    #packet.delivered value denoting the end of a packet-timed round trip.
    next_round_delivered: int = 0

    #A boolean that is true if and only if a connection is restarting after
    #being idle.
    idle_restart: bool = False

    #2.9.1.  Data Rate Network Path Model Parameters
    #The windowed maximum recent bandwidth sample - obtained using the BBR
    #delivery rate sampling algorithm
    #[draft-cheng-iccrg-delivery-rate-estimation] - measured during the current
    #or previous bandwidth probing cycle (or during Startup, if the flow is
    #still in that state).  (Part of the long-term model.)
    max_bw: int = 0

    #The long-term maximum sending bandwidth that the algorithm estimates will
    #produce acceptable queue pressure, based on signals in the current or
    #previous bandwidth probing cycle, as measured by loss.  (Part of the
    #long-term model.) 
    bw_hi: int = MAX_INT   

    #The short-term maximum sending bandwidth that the algorithm estimates is
    #safe for matching the current network path delivery rate, based on any
    #loss signals in the current bandwidth probing cycle.  This is generally
    #lower than max_bw or bw_hi (thus the name).  (Part of the short-term
    #model.)
    bw_lo: int = MAX_INT

    #The maximum sending bandwidth that the algorithm estimates is appropriate
    #for matching the current network path delivery rate, given all available
    #signals in the model, at any time scale.  It is the min() of max_bw,
    #bw_hi, and bw_lo.
    bw: int = 0

    #2.9.2.  Data Volume Network Path Model Parameters
    #The windowed minimum round-trip time sample measured over the last
    #MinRTTFilterLen = 10 seconds.  This attempts to estimate the two-way
    #propagation delay of the network path when all connections sharing a
    #bottleneck are using BBR, but also allows BBR to estimate the value
    #required for a bdp estimate that allows full throughput if there are
    #legacy loss-based Reno or CUBIC flows sharing the bottleneck.
    min_rtt: float = float("inf")

    #The estimate of the network path's BDP (Bandwidth-Delay Product), computed
    #as: BBR.bdp = BBR.bw * BBR.min_rtt.
    bdp: int = 0

    #A volume of data that is the estimate of the recent degree of aggregation
    #in the network path.
    extra_acked: int = 0

    #The estimate of the minimum volume of data necessary to achieve full
    #throughput when using sender (TSO/GSO) and receiver (LRO, GRO) host
    #offload mechanisms.
    offload_budget: int = 0

    #The estimate of the volume of in-flight data required to fully utilize the
    #bottleneck bandwidth available to the flow, based on the BDP estimate
    #(BBR.bdp), the aggregation estimate (BBR.extra_acked), the offload budget
    #(BBR.offload_budget), and BBRMinPipeCwnd.
    max_inflight: int = 0

    #Analogous to BBR.bw_hi, the long-term maximum volume of in-flight data
    #that the algorithm estimates will produce acceptable queue pressure, based
    #on signals in the current or previous bandwidth probing cycle, as measured
    #by loss.  That is, if a flow is probing for bandwidth, and observes that
    #sending a particular volume of in-flight data causes a loss rate higher
    #than the loss rate objective, it sets inflight_hi to that volume of data.
    #(Part of the long-term model.)
    inflight_hi: int = MAX_INT

    #Analogous to BBR.bw_lo, the short-term maximum volume of in-flight data
    #that the algorithm estimates is safe for matching the current network path
    #delivery process, based on any loss signals in the current bandwidth
    #probing cycle.  This is generally lower than max_inflight or inflight_hi
    #(thus the name).  (Part of the short-term model.)
    inflight_lo: int = MAX_INT

    #2.10.  State for Responding to Congestion
    #a 1-round-trip max of delivered bandwidth (rs.delivery_rate).
    bw_latest: int = 0

    #a 1-round-trip max of delivered volume of data (rs.delivered).
    inflight_latest: int = 0

    #2.11.  Estimating BBR.max_bw
    #The filter for tracking the maximum recent rs.delivery_rate sample, for
    #estimating BBR.max_bw.
    max_bw_filter: Minmax = Minmax(0)

    #The virtual time used by the BBR.max_bw filter window.  Note that
    #BBR.cycle_count only needs to be tracked with a single bit, since the
    #BBR.MaxBwFilter only needs to track samples from two time slots: the
    #previous ProbeBW cycle and the current ProbeBW cycle.
    cycle_count: int = 0

    #2.12.  Estimating BBR.extra_acked
    #the start of the time interval for estimating the excess amount of data
    #acknowledged due to aggregation effects.
    extra_acked_interval_start: float = Now()

    #the volume of data marked as delivered since
    #BBR.extra_acked_interval_start.
    extra_acked_delivered: int = 0

    #BBR.ExtraACKedFilter: the max filter tracking the recent maximum degree of
    #aggregation in the path.
    extra_acked_filter: Minmax = Minmax(0)

    #2.13.  Startup Parameters and State
    #A boolean that records whether BBR estimates that it has ever fully
    #utilized its available bandwidth ("filled the pipe").
    filled_pipe: bool = False

    #A recent baseline BBR.max_bw to estimate if BBR has "filled the pipe" in
    #Startup.
    full_bw: int = 0

    #The number of non-app-limited round trips without large increases in
    #BBR.full_bw.
    full_bw_count: int = 0

    #2.14.1.  Parameters for Estimating BBR.min_rtt
    #The wall clock time at which the current BBR.min_rtt sample was obtained.
    min_rtt_stamp: float = Now()

    #2.14.2.  Parameters for Scheduling ProbeRTT
    #The minimum RTT sample recorded in the last ProbeRTTInterval.
    probe_rtt_min_delay: float = float("inf")

    #The wall clock time at which the current BBR.probe_rtt_min_delay sample
    #was obtained.
    probe_rtt_min_stamp: float= Now()

    #A boolean recording whether the BBR.probe_rtt_min_delay has expired and is
    #due for a refresh with an application idle period or a transition into
    #ProbeRTT state.
    probe_rtt_expired: bool = False

    #Others
    #A state indicating we are in the recovery.
    in_recovery: bool = False

    #Start time of the connection.
    start_time: float

    #Saved cwnd before loss recovery.
    prior_cwnd: int = 0

    #Whether we have a bandwidth probe samples.
    bw_probe_samples: bool = False

    #Others
    probe_up_cnt: int = 0

    prior_bytes_in_flight: int = 0

    probe_rtt_done_stamp: Optional[float] = None

    probe_rtt_round_done: bool = False

    bw_probe_wait: float = 0.0

    rounds_since_probe: int = 0

    cycle_stamp: float = Now()

    ack_phase: BBR2ACKPhase = BBR2ACKPhase.INIT

    bw_probe_up_rounds: int = 0

    bw_probe_up_acks: int = 0

    loss_round_start: bool = False

    loss_round_delivered: int = 0

    loss_in_round: bool = False

    loss_events_in_round: int = 0

    # the congestion window used by the recovery
    cwnd : int = K_INITIAL_WINDOW

    # The number of bytes in flight 
    # TODO : update it when sending/receiving a packet
    bytes_in_flight : int = 0

    # The number of lost bytes
    # TODO : update it when a packet is lost
    bytes_lost : int = 0