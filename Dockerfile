FROM 217386048230.dkr.ecr.us-east-1.amazonaws.com/suricata:latest

ADD test-stitcher /usr/bin/test-stitcher
ADD pcap/* /mnt/run/pcap/
ADD configs/* /mnt/run/configs/
ADD *.config /mnt/run/

ENTRYPOINT ["/usr/bin/suricata"]
