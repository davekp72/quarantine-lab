    iifname "__LAN__" oifname "__WAN__" ip protocol icmp accept
    iifname "__LAN__" oifname "__WAN__" ip6 nexthdr icmpv6 accept
    # DNS / DoT to WAN blocked — redirected to gateway in prerouting
    iifname "__LAN__" oifname "__WAN__" udp dport { 53, 853 } drop
    iifname "__LAN__" oifname "__WAN__" tcp dport { 53, 853 } drop
    # No blanket LAN→WAN accept — remaining traffic is dropped (policy drop).
