#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

/* Ethernet header */
struct ethheader {
  u_char ether_dhost[6];  // destination host address
  u_char ether_shost[6];  // source host address
  u_short ether_type;     // protocol type (IP, ARP, RARP, etc)
};

/* IP Header */
struct ipheader {
  unsigned char iph_ihl : 4,     // IP header length
      iph_ver : 4;               // IP version
  unsigned char iph_tos;         // Type of service
  unsigned short int iph_len;    // IP Packet length (data + header)
  unsigned short int iph_ident;  // Identification
  unsigned short int iph_flags : 3,
      iph_offset : 13;            // Fragmentation flags, Flags offset
  unsigned char iph_ttl;          // Time to Live
  unsigned char iph_protocol;     // Protocol type
  unsigned short int iph_chksum;  // IP datagram checksum
  struct in_addr iph_sourceip;    // Source IP address
  struct in_addr iph_destip;      // Destination IP address
};

/* TCP Header */
struct tcpheader {
  u_short tcph_srcport;                       // source port
  u_short tcph_destport;                      // destination port
  u_int tcph_seqnum;                          // sequence number
  u_int tcph_acknum;                          // acknowledgement number
  u_char tcph_reserved : 4, tcph_offset : 4;  // data offset
  u_char tcph_flags;                          // control flags
  u_short tcph_win;                           // window
  u_short tcph_chksum;                        // checksum
  u_short tcph_urgptr;                        // urgent pointer
};

// only tcp protocol, 메세지도 출력하면 좋음 -> nc 명령어로 테스트 해보기
// Ethernet Header : src mac / dst mac 출력
// IP Header : src ip / dst ip 출력
// TCP Header : src port / dst port 출력
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == ETHERTYPE_IP) {  // ETHERTYPE_IP for IP packets
    struct ipheader *ip =
        (struct ipheader *)(packet + sizeof(struct ethheader));

    // From이 SRC_PC_IP이고 To가 DST_PC_IP인 경우 또는 그 반대인 경우만
    struct in_addr target_ip1, target_ip2;
    inet_pton(AF_INET, "SRC_PC_IP", &target_ip1);
    inet_pton(AF_INET, "DST_PC_IP", &target_ip2);
    if (!((ip->iph_sourceip.s_addr == target_ip1.s_addr &&
           ip->iph_destip.s_addr == target_ip2.s_addr) ||
          (ip->iph_sourceip.s_addr == target_ip2.s_addr &&
           ip->iph_destip.s_addr == target_ip1.s_addr)))
      return;

    printf("Ethernet Header\n");

    printf("       From: ");
    for (int i = 0; i < 6; i++) {
      printf("%02x", eth->ether_shost[i]);
      if (i != 5) {
        printf(":");
      }
    }
    printf("\n");

    printf("         To: ");
    for (int i = 0; i < 6; i++) {
      printf("%02x", eth->ether_dhost[i]);
      if (i != 5) {
        printf(":");
      }
    }
    printf("\n");

    printf("IP Header\n");
    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));

    /* determine protocol */
    switch (ip->iph_protocol) {
      case IPPROTO_TCP:
        printf("TCP Header\n");
        struct tcpheader *tcp =
            (struct tcpheader *)(packet + sizeof(struct ethheader) +
                                 sizeof(struct ipheader));
        printf("   Src port: %d\n", ntohs(tcp->tcph_srcport));
        printf("   Dst port: %d\n", ntohs(tcp->tcph_destport));

        // TCP 헤더 이후의 데이터만 출력, ethheader + ipheader + tcpheader
        // 사이즈 + 12byte (옵션 혹은 padding으로 예상되는 데이터,,)
        int data_offset = sizeof(struct ethheader) + sizeof(struct ipheader) +
                          sizeof(struct tcpheader) + 12;
        int data_len = header->len - data_offset;

        // Message 출력
        printf("Message: ");

        for (int i = data_offset; i < header->len; i++) {
          // ASCII 범위 내에 있는 문자만 출력
          if (packet[i] >= 32 && packet[i] <= 126) {
            printf("%c", packet[i]);
          }
        }
        printf("\n");

        break;
      default:
        printf("   Protocol: others\n");
        break;
    }
  }
}

int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  // Step 1: Open live pcap session on NIC with name <your NIC>
  handle = pcap_open_live("<your NIC>", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  struct bpf_program fp;
  char filter_exp[] = "ip proto tcp";
  pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, 0, got_packet, NULL);

  pcap_close(handle);  // close the handle
  return 0;
}
