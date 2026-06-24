# L4AntiDoS: Monitoraggio Dinamico e Mitigazione di Attacchi TCP/UDP/ICMP Flooding in Reti SDN

Repository ufficiale del progetto finale per il corso di **Networks and Cloud Infrastructures** (Anno Accademico 2025/2026) presso l'**Università degli Studi di Napoli Federico II** (Scuola Politecnica e delle Scienze di Base - Corso di Laurea in Ingegneria Informatica).

Membri del Team
*   [Valentino Alberobello](https://www.linkedin.com/in/valentino-alberobello-1009233ba/)
*   [Angela Dalia](https://www.linkedin.com/in/angela-dalia-735688251/)
*   [Tuo Nome](www.linkedin.com/in/daniele-di-sarno-856688225)

---

Obiettivi del Progetto
Nel panorama Software-Defined Networking (SDN), la separazione tra il piano di controllo e il piano dei dati espone il controller a potenziali attacchi Denial of Service (DoS). 

**L4AntiDoS** implementa un meccanismo di difesa automatizzato basato su **Ryu Controller** e **OpenFlow v1.3** capace di:
1. Rilevare flussi anomali di livello 3 e 4 (ICMP Echo Requests, TCP, UDP).
2. Calcolare **soglie di traffico dinamiche** basate sulla reale larghezza di banda nominale impostata sulle porte dei link.
3. Isolare chirurgicamente l'host attaccante applicando regole globali di `DROP` senza compromettere le comunicazioni dei nodi legittimi.

A differenza delle soluzioni a soglia statica, l'applicazione adatta in modo del tutto autonomo le proprie tolleranze al mutare della topologia di rete grazie alla lettura automatica dei vincoli di banda strutturati in un file di configurazione JSON (`/tmp/port_bw.json`).

---

Architettura e Variante di Mitigazione
Il sistema è stato validato sperimentalmente su due topologie in ambiente emulato **Mininet**:
*   **Topologia Standard:** 3 Host ed un'infrastruttura a 2 Switch logici (S1, S2).
*   **Topologia Alternativa:** Scenario esteso a 4 Host e 3 Switch logici per validare la nativa capacità di adattamento dinamico del controller senza alcuna modifica al codice sorgente.

Meccanismo di Un-BAN Temporaneo
È stata sviluppata una variante avanzata del controller (`ryu_controller_with_unban.py`) che include una routine asincrona di sblocco automatico. Dopo l'applicazione del BAN, il sistema attende 60 secondi prima di inviare i messaggi `OFPFC_DELETE` agli switch, ripristinando l'host ed evitando isolamenti permanenti causati da potenziali falsi positivi.

---

Come Eseguire il Progetto

Prerequisiti Ambiente
*   Oracle VM VirtualBox (Ubuntu Server)
*   Mininet
*   Ryu SDN Framework
*   Tshark / D-ITG (per cattura e generazione traffico)

Istruzioni per l'Avvio

1. Avviare il Controller Ryu** (scegliere una delle due versioni):
   
   # Versione Standard (BAN permanente)
   ryu-manager ryu_controller.py
   
   # Versione Avanzata (con Un-BAN dopo 60s)
   ryu-manager ryu_controller_with_unban.py

2. Avviare la Topologia Mininet (in un altro terminale):

   # Topologia principale (2 switch, 3 host)
   sudo python3 topology.py
   
   # Topologia alternativa (3 switch, 4 host)
   sudo python3 topology2.py

3. Simulazione dell'Attacco con D-ITG:
Sul terminale Mininet, impostare un host in ascolto (es. h2) e generare traffico UDP anomalo dall'host attaccante (es. h3):

  mininet> h2 ITGRecv &
  mininet> h3 ITGSend -a 10.0.0.2 -T UDP 1200 -c 5000
