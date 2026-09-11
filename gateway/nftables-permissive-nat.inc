    # Force guest DNS onto the gateway (dnsmasq / FakeNet listener)
    iifname "__LAN__" udp dport 53 redirect to :53
    iifname "__LAN__" tcp dport 53 redirect to :53
