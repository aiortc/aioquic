from .congestion import Now
from ..recovery import QuicPacketRecovery, K_MIN_RTT
from ..packet_builder import QuicSentPacket

BETA_DELIVERY_RATE = 7/8

# a class to collect information about the rate sample
class RateSample:
    def __init__(self, recovery) -> None:
        self.packet_info = {} # store the informations about Transport controler when packet was sent
        self.delivered = 0
        self.prior_delivered = 0
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

    def delivered(self):
        return self.delivered

    def sample_delivered(self):
        return self.delivered - self.prior_delivered

    def get_packet_info(self, packet: QuicSentPacket):
        return self.packet_info[packet.packet_number]
    
    def add_packet_info(self, packet: QuicSentPacket, now : float):
        self.packet_info[packet.packet_number] = {
            "delivered" : self.delivered,
            "lost" : self.lost,
            "inflight" : self.inflight,
            "delivery_rate" : self.delivery_rate,
            "time" : now
        }

    def rm_packet_info(self, packet : QuicSentPacket):
        try:
            del self.packet_info[packet.packet_number]
        except:
            pass
    
    def update_delivery_rate(self):
        # update delivery rate
        self.delivery_rate = BETA_DELIVERY_RATE * self.delivery_rate + (1-BETA_DELIVERY_RATE)*((self.delivered - self.prior_delivered) / self.interval)
        #self.delivery_rate = (self.delivered - self.prior_delivered) / self.interval
        self.delivery_rate = max(self.delivery_rate, 1000*8)

    def on_ack(self, packet : QuicSentPacket, now : float):
        self.delivered += packet.sent_bytes

        self.interval = now - self.get_packet_info(packet)["time"]

        if (self.prior_delivered == None or self.prior_delivered < self.get_packet_info(packet)['delivered']):
            self.prior_delivered = self.get_packet_info(packet)['delivered']
        
        self.update_delivery_rate()
        
    
    def on_sent(self, packet : QuicSentPacket, now : float):
        self.inflight += packet.sent_bytes
        self.add_packet_info(packet, now)
        if (self.start_time == None):
            self.start_time = now

    def on_expired(self, packet : QuicSentPacket):
        self.inflight -= packet.sent_bytes
        self.rm_packet_info(packet)

    def on_lost(self, packet : QuicSentPacket, now : float):
        self.inflight -= packet.sent_bytes
        self.lost += packet.sent_bytes
        self.lost_timestamp = packet.sent_time
        self.interval = now - self.get_packet_info(packet)["time"]
        self.update_delivery_rate()