from ..packet_builder import QuicSentPacket

BETA_DELIVERY_RATE = 3/4

# a class to collect information about the rate sample
class RateSample:
    def __init__(self) -> None:
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
        self.number_ack = 0

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
        res = self.packet_info.get(packet.packet_number, None)
        return res
    
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
    
    def update_delivery_rate(self, packet):
        # update delivery rate
        if self.number_ack >= 20:
            # delivery_rate should be more stable, use a beta increase
            self.delivery_rate = BETA_DELIVERY_RATE * self.delivery_rate + (1-BETA_DELIVERY_RATE)*((self.delivered - self.get_packet_info(packet)["delivered"]) / self.interval)
        else:
            self.delivery_rate = (self.delivered - self.get_packet_info(packet)["delivered"]) / self.interval

        self.delivery_rate = max(self.delivery_rate, 1000)  # at least 1kBps

    def on_ack(self, packet : QuicSentPacket, now : float):
        self.delivered += packet.sent_bytes
        self.number_ack += 1

        if self.get_packet_info(packet) == None:
            return

        self.interval = now - self.get_packet_info(packet)["time"]

        if (self.prior_delivered == None or self.prior_delivered < self.get_packet_info(packet)['delivered']):
            self.prior_delivered = self.get_packet_info(packet)['delivered']
        
       
        self.update_delivery_rate(packet)
        
    
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
        if self.get_packet_info(packet) == None:
            return
        self.interval = now - self.get_packet_info(packet)["time"]
        self.update_delivery_rate(packet)

    def add_attributes(self, dict):
        dict["delivered"] = self.delivered
        dict["rs_interval"] = self.interval
        dict["rs_lost"] = self.lost
        dict["delivery_rate"] = self.delivery_rate
        return dict