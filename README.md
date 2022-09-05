# Documentazione

## Introduzione

**PacketSniffer** è un'applicazione multipiattaforma dedicata all'attività di intercettazione passiva dei dati che transitano in una rete telematica ( anche noto come attività di **sniffing** ).

All'avvio il programma mostrerà i dispositivi di rete individuati e chiederà all'utente su quale dispositivo si voglia far partire il processo di sniffing.

L'applicazione imposterà l'adattatore di rete in modalità promiscua e salverà i dettagli del traffico processato ( indirizzi IP, porte, protocollo, timestamp inziale, timestamp finale ) su un report testuale.

Il processo di sniffing può essere messo in pausa in qualunque momento ( premendo il tasto **s** dalla tastiera ) per poi essere ripreso ( premendo il tasto **r** dalla tastiera ). L'utente può inoltre decidere di terminare il programma ( premendo il tasto **q** dalla tastiera ).


## Usage

- ### Linux/MAC
    - Prerequisiti
      `sudo apt-get install libcap-dev`
    - Avvio
      `sudo cargo run -- [OPTIONS]`

- ### Windows
    - Prerequisiti
        1. Installare [WinPcap](https://www.winpcap.org/devel.htm)
        2. Impostare la variabile d'ambiente
    - Avvio
      `cargo run -- [OPTIONS]`
    - OPTIONS:
      // Immagine da mettere ( Img folder in Github )

## Protocols
- ethernet
- ipv4
- ipv6
- tcp
- udp
- dns


## Dipendenze
**pcap** = "0.9.2"  
**pktparse** = "0.7.1"  
**dns-parser** = "0.8.0"  
**clap** = { version = "3.2.14", features = ["derive"] }  
**colored** = "2.0.0"  
**chrono** = "0.4.20"  
**tokio** = { version = "1.20.1", features = ["full"] }

`