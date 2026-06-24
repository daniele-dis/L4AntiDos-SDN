from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, ipv4, icmp
from ryu.lib import hub
import json
 
class L4AntiDoS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 
    MONITOR_INTERVAL = 0.5
    THRESHOLD_RATIO  = 0.03
    FALLBACK_BW_MBPS = 10
    BITS_PER_PKT     = 12000
 
    def __init__(self, *args, **kwargs):
        super(L4AntiDoS, self).__init__(*args, **kwargs)
        self.mac_to_port     = {}
        self.datapaths       = {}
        self.flow_history    = {}
        self.already_blocked = set()
        self.mac_owner       = {}
        self.port_threshold  = {}
 
        # Carica la mappa bw scritta dalla topologia
        try:
            with open('/tmp/port_bw.json', 'r') as f:
                raw = json.load(f)
            self.port_bw_map = {
                tuple(int(x) for x in k.split(',')): v
                for k, v in raw.items()
            }
            print(f"[*] Mappa bw caricata: {self.port_bw_map}")
        except Exception as e:
            print(f"[!] port_bw.json non trovato: {e} — fallback {self.FALLBACK_BW_MBPS} Mbps")
            self.port_bw_map = {}
 
        self.monitor_thread = hub.spawn(self._monitor)
 
    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
 
    # Converte la larghezza di banda (Mbps) in una soglia di pacchetti per intervallo di monitoraggio.
    def _bw_to_threshold(self, bw_mbps):
        bw_bps = bw_mbps * 1_000_000
        pkts_per_sec = bw_bps * self.THRESHOLD_RATIO / self.BITS_PER_PKT
        return max(1, int(pkts_per_sec * self.MONITOR_INTERVAL))
 
    # Recupera la soglia di pacchetti per un MAC sorgente, usando un valore di fallback se non trovato.
    def _get_threshold_for_src(self, dpid, src_mac):
        port_no = self.mac_to_port.get(dpid, {}).get(src_mac)
        if port_no is None:
            return self._bw_to_threshold(self.FALLBACK_BW_MBPS)
        return self.port_threshold.get(
            (dpid, port_no),
            self._bw_to_threshold(self.FALLBACK_BW_MBPS)
        )
 
    # Invia un messaggio FlowMod allo switch per installare una nuova regola di flusso OpenFlow.
    def add_flow(self, datapath, priority, match, actions, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod  = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            idle_timeout=idle, hard_timeout=hard,
            match=match, instructions=inst
        )
        datapath.send_msg(mod)
 
    # Richiede allo switch la descrizione dettagliata e lo stato di tutte le sue porte.
    def _request_port_desc(self, datapath):
        req = datapath.ofproto_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)
 
    # ------------------------------------------------------------------
    # Funzione che viene invocata quando uno switch si connette al controller per la prima volta.
    # ------------------------------------------------------------------
 
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
 
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})
 
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
 
        self._request_port_desc(datapath)
        print(f"[*] Anti-DoS attivo su Switch ID: {datapath.id}")
 
    # ------------------------------------------------------------------
    # Riceve ed elabora la descrizione delle porte richiesta dalla funzione switch_features_handler alla connessione dello switch.
    # ------------------------------------------------------------------
 
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def _port_desc_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dpid     = datapath.id
 
        for port in ev.msg.body:
            if port.port_no > 0xffffff00:
                continue
 
            key     = (dpid, port.port_no)
            bw_mbps = self.port_bw_map.get(key, self.FALLBACK_BW_MBPS)
            thr     = self._bw_to_threshold(bw_mbps)
            self.port_threshold[key] = thr
            print(f"  [PORTA] dpid={dpid} porta={port.port_no} "
                  f"→ {bw_mbps} Mbps → soglia={thr} pkts/0.5s")
 
    # ------------------------------------------------------------------
    # Thread Monitor che periodicamente invia richieste di statistiche dei flussi a tutti gli switch connessi.
    # ------------------------------------------------------------------
 
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(self.MONITOR_INTERVAL)
 
    # ------------------------------------------------------------------
    # Gestisce i pacchetti sconosciuti dello switch inoltrati al controller
    # associando ogni MAC alla sua porta di ingresso e installando le regole di flusso sugli switch connessi.
    # ------------------------------------------------------------------
 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
 
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
 
        if eth.ethertype == 0x88cc:
            return
 
        src, dst = eth.src, eth.dst
        dpid     = datapath.id
 
        if src not in self.mac_owner:
            self.mac_owner[src] = dpid
 
        # Scarta silenziosamente i pacchetti provenienti da MAC già bannati.
        # Le regole OpenFlow drop su tutti gli switch già bloccano il traffico in rete;
        # questo return impedisce ulteriori elaborazioni sul controller.
        if src in self.already_blocked:
            return
 
        self.mac_to_port[dpid][src] = in_port
 
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]
 
        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)

                # Monitoriamo ICMP, TCP e UDP
                if ip_pkt.proto in [1, 6, 17]:
                    # ICMP / ping
                    if ip_pkt.proto == 1:
                        icmp_pkt = pkt.get_protocol(icmp.icmp)

                        # Monitoro solo le richieste ping: Echo Request
                        # Così evito che la risposta della vittima venga vista come attacco inverso
                        if icmp_pkt and icmp_pkt.type == 8:
                            match = parser.OFPMatch(
                                eth_type=ether.ETH_TYPE_IP,
                                ip_proto=1,
                                icmpv4_type=8,
                                in_port=in_port,
                                eth_src=src,
                                eth_dst=dst
                            )
                            self.add_flow(datapath, 10, match, actions, idle=10)

                        # Echo Reply o altri ICMP: li inoltro normalmente, ma non li monitoro come DoS
                        else:
                            match = parser.OFPMatch(
                                eth_type=ether.ETH_TYPE_IP,
                                ip_proto=1,
                                in_port=in_port,
                                eth_src=src,
                                eth_dst=dst
                            )
                            self.add_flow(datapath, 5, match, actions, idle=10)

                    # TCP e UDP: lascio invariato, quindi DITG continua a funzionare come prima
                    else:
                        match = parser.OFPMatch(
                            eth_type=ether.ETH_TYPE_IP,
                            ip_proto=ip_pkt.proto,
                            in_port=in_port,
                            eth_src=src,
                            eth_dst=dst
                        )
                        self.add_flow(datapath, 10, match, actions, idle=10)    
                else:
                    match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                            eth_src=src, eth_dst=dst)
                    self.add_flow(datapath, 5, match, actions, idle=20)
            elif eth.ethertype == ether.ETH_TYPE_ARP:
                match = parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP,
                                        eth_src=src, eth_dst=dst)
                self.add_flow(datapath, 20, match, actions, idle=60)
    
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
 
 # ------------------------------------------------------------------
    # Analizza i contatori dei pacchetti ricevuti dagli switch a seguito di richiesta del monitor.
    # Rileva le anomalie in modo chirurgico differenziando accuratamente per porta d'ingresso.
    # ------------------------------------------------------------------
 
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body     = ev.msg.body
        datapath = ev.msg.datapath
        dpid     = datapath.id
 
        for stat in body:
            # Monitoriamo solo i flussi con priorità 10 (ICMP/TCP/UDP)
            if stat.priority != 10:
                continue
            if stat.match.get('ip_proto') == 1 and stat.match.get('icmpv4_type') != 8:
                continue

            eth_src = stat.match.get('eth_src')
            eth_dst = stat.match.get('eth_dst')
 
            if not eth_src or eth_src in self.already_blocked:
                continue
 
            # FONDAMENTALE: Controlliamo l'host SOLO sullo switch a cui è fisicamente collegato!
            if dpid != self.mac_owner.get(eth_src):
                continue
 
            # Recuperiamo la porta d'ingresso
            in_port = stat.match.get('in_port')
            if in_port is None and eth_src in self.mac_to_port.get(dpid, {}):
                in_port = self.mac_to_port[dpid][eth_src]
 
            if in_port is None:
                continue
 
            # CREIAMO UNA CHIAVE UNIVOCA BLINDATA PER QUESTO SPECIFICO SWITCH
            flow_key = (dpid, in_port, eth_src, eth_dst)
            current_pkts = stat.packet_count
            
            # Se è la prima volta che vediamo questo flusso, inizializziamo la storia e saltiamo il calcolo del rate
            if flow_key not in self.flow_history:
                self.flow_history[flow_key] = current_pkts
                continue
 
            prev_pkts = self.flow_history[flow_key]
            rate = current_pkts - prev_pkts
 
            # SE IL RATE E' 0 SIGNIFICA CHE E' UN RECORD DUPLICATO NELLO STESSO CICLO: LO IGNORIAMO SECCAMENTE
            if rate <= 0:
                continue
 
            # Aggiorniamo la storia SOLO se il rate è valido e maggiore di zero
            self.flow_history[flow_key] = current_pkts
 
            # Recuperiamo la soglia corretta basandoci sulla porta reale dell'attaccante
            threshold = self._get_threshold_for_src(dpid, eth_src)
 
            if rate > threshold:
                print("\n" + "="*60)
                print(f"  [ALERT] DoS rilevato su switch {dpid}")
                print(f"  Attaccante : {eth_src}")
                print(f"  Vittima    : {eth_dst}")
                print(f"  Rate       : {rate} pkts/0.5s  >  soglia {threshold} pkts/0.5s")
                print(f"  Azione     : BAN applicato su tutta la rete")
                print("="*60 + "\n")
 
                self.already_blocked.add(eth_src)
 
                for dp_to_ban in self.datapaths.values():
                    p = dp_to_ban.ofproto_parser
 
                    # DROP Globale su tutta la topologia per bloccare l'attaccante
                    match_src = p.OFPMatch(eth_src=eth_src, eth_type=ether.ETH_TYPE_IP)
                    self.add_flow(dp_to_ban, 100, match_src, [])
                    match_dst = p.OFPMatch(eth_dst=eth_src, eth_type=ether.ETH_TYPE_IP)
                    self.add_flow(dp_to_ban, 100, match_dst, [])

                # Fai partire in background la routine di sblocco pulita
                hub.spawn(self._unban_host, eth_src)
 
            else:
                print(f"[OK] {eth_src[:8]}.. porta={in_port} rate={rate} pkts/0.5s — sotto soglia ({threshold})")

    def _unban_host(self, eth_src):
        hub.sleep(60)

        # Rimuovi le regole DROP dagli switch PRIMA di aggiornare lo stato
        for dp in self.datapaths.values():
            p, ofp = dp.ofproto_parser, dp.ofproto
            for match in [p.OFPMatch(eth_src=eth_src, eth_type=ether.ETH_TYPE_IP),
                          p.OFPMatch(eth_dst=eth_src, eth_type=ether.ETH_TYPE_IP)]:
                dp.send_msg(p.OFPFlowMod(
                    datapath=dp, command=ofp.OFPFC_DELETE,
                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=match
                ))

        # Pulisci lo stato del controller
        self.already_blocked.discard(eth_src)
        for k in [k for k in self.flow_history if k[2] == eth_src or k[3] == eth_src]:
            self.flow_history.pop(k, None)

        print(f"\n[*] [UNBAN] {eth_src} sbloccato, regole DROP rimosse.")