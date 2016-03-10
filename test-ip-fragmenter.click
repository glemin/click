// Test IPFragmenter

InfiniteSource(LIMIT 5) -> UDPIPEncap(1.0.0.1, 1234, 2.0.0.2, 1234) -> EtherEncap(0x0800, 00:0a:95:9d:68:16, 00:0a:95:9d:68:17) -> ToDump(bla.dump) -> Strip(14) -> fr::IPFragmenter(68) -> Unstrip(14) -> ToDump(bla2.dump) -> Discard;

fr[1] -> ToDump(bla3.dump) -> ICMPError(18.26.4.24, 3, 4) -> ToDump(bla4.dump) -> Discard;
