from .congestion import Now
from ..recovery import QuicPacketRecovery
from ..packet_builder import QuicSentPacket

# a class to collect information about the rate sample
class RateSample:
    def __init__(self, recovery) -> None:
        self.packet_info = {} # store the informations about Transport controler when packet was sent
        self.delivered = 0
        self.lost = 0
        self.inflight = 0
        self.delivery_rate = 0
        self.app_limited = False
        self.lost_timestamp = None
        self.interval = 0
        self.start_time = None
        self.recovery : QuicPacketRecovery = recovery

    def in_congestion_recovery(self, packet):
        # check if we were in congestion recovery at time when packet was sent
        return self.lost_timestamp != None and packet.sent_time <= self.lost_timestamp

    def update_app_limited(self, value):
        # consider for the moment that there's no application limitation
        pass

    def sample_delivered(self):
        # let's just make something simple for now
        return self.delivered

    def get_packet_info(self, packet: QuicSentPacket):
        return self.packet_info[packet.packet_number]
    
    def add_packet_info(self, packet: QuicSentPacket):
        self.packet_info[packet.packet_number] = {
            "delivered" : self.delivered,
            "lost" : self.lost,
            "inflight" : self.inflight,
            "delivery_rate" : self.delivery_rate
        }

    def rm_packet_info(self, packet : QuicSentPacket):
        try:
            del self.packet_info[packet.packet_number]
        except:
            pass
    
    def update_delivery_rate(self, packet):
        # update delivery rate
        # use a minimum rtt of 1ms
        self.delivery_rate = (self.delivered - self.prior_delivered) / max(self.recovery._rtt_smoothed, 0.001)

    def on_ack(self, packet : QuicSentPacket):
        self.inflight = max(self.inflight - packet.sent_bytes, 0)
        self.delivered += packet.sent_bytes

        self.prior_delivered = self.get_packet_info(packet)['delivered']
        
        self.update_delivery_rate(packet)
        
    
    def on_sent(self, packet : QuicSentPacket):
        self.inflight += packet.sent_bytes
        self.add_packet_info(packet)
        if (self.start_time == None):
            self.start_time = Now()
            self.start_time_packet = packet.sent_time

    def on_expired(self, packet : QuicSentPacket):
        self.inflight -= packet.sent_bytes
        self.rm_packet_info(packet)

    def on_lost(self, packet : QuicSentPacket):
        self.inflight -= packet.sent_bytes
        self.lost += packet.sent_bytes
        self.lost_timestamp = packet.sent_time
        self.update_delivery_rate(packet)