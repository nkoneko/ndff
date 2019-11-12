#include "ndff.hpp"
#include <ndpi_typedefs.h>
#include <pcap.h>
#include <arpa/inet.h>

namespace dena::security {
    constexpr int ETH_P_IP = 0x0800;
    constexpr int ETH_P_IPV6 = 0x86dd;
    constexpr int SNAP = 0xaa;

    inline u_int16_t get_upper_layer_protocol_en(u_int16_t eth_offset, const u_char *packet, int *type)
    {
        /* ここの処理は https://tech.nikkeibp.co.jp/it/article/COLUMN/20070911/281665/ あたり読むと理解できそう */
        auto ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
        auto ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
        auto check = ntohs(ethernet->h_proto);
        int pyld_eth_len = 0;
            
        /* MACアドレスの後ろのバイトは、LLC拡張なしのIEEE 802.3フレームでは「プロトコルのタイプ」、LLC拡張では「長さ」です。1500以下か1536以上かでどちらの値か判別できます。 */
        if(check <= 1500) {
            /* LLC拡張ありのフレームの場合はここの値が長さを表し、1500以下の値になっている */
            pyld_eth_len = check;
        } else if (check >= 1536) {
            /* LLC拡張なしの802.3フレームではここがペイロードの長さではなくて、プロトコルタイプになっている。よって、1536以上の値なら、ここでTypeの取得は終わり */
            *type = check;
        }

        /* LLC拡張のある場合。(この場合はcheckが1500以下になっているので、上の行でpyld_eth_lenの代入がなく、0のままでこちらの分岐に進む) */
        if(pyld_eth_len != 0) {
            auto llc = (struct ndpi_llc_header_snap *)(&packet[ip_offset]);
            /* DSAP, SSAP が SNAP のときは、LLCの4バイトの後ろに SNAPってデータがあって、そこにProtocol IDが詰まっている */
            if(llc->dsap == SNAP || llc->ssap == SNAP) {
                *type = llc->snap.proto_ID;
                ip_offset += + 8;
            }
        }
        return ip_offset;
    }

    inline u_int16_t get_upper_layer_protocol_wlan(u_int16_t eth_offset, const u_char *packet, int +type)
    {
        int wifi_len;
        auto radiotap = (struct ndpi_radiotap_header *) &packet[eth_offset];
        auto radio_len = radiotap->len;

        /* Check Bad FCS presence */
        if ((radiotap->flags & BAD_FCS) == BAD_FCS)
        {
            //malformed_pkts += 1;
            return -1;
        }
        fcs = header->len - 4;
            
        /* Calculate 802.11 header length (variable) */
        auto wifi = (struct ndpi_wifi_header *)(packet + eth_offset + radio_len);
        auto fc = wifi->fc;

        /* check wifi data presence */
        if (FCF_TYPE(fc) == WIFI_DATA)
        {
            if ((FCF_TO_DS(fc) && FCF_FROM_DS(fc) == 0x0) ||
                (FCF_TO_DS(fc) == 0x0 && FCF_FROM_DS(fc)))
                wifi_len = 26; /* + 4 byte fcs */
        }
        else /* no data frames */
            return -1;

        /* Check ether_type from LLC */
        auto llc = (struct ndpi_llc_header_snap *)(packet + eth_offset + wifi_len + radio_len);
        if (llc->dsap == SNAP)
            *type = ntohs(llc->snap.proto_ID);

        /* Set IP header offset */
        return wifi_len + radio_len + sizeof(struct ndpi_llc_header_snap) + eth_offset;
    }

    inline u_int16_t get_upper_layer_protocol(int datalink_type, u_int16_t eth_offset, const u_char *packet, int *type)
    {
        switch (datalink_type) {
        case DLT_NULL:
            auto a = ntohl(*((u_int32_t*)&packet[eth_offset]));
            *type = a == 2 ? ETH_P_IP : ETH_P_IPV6;
            return 4 + eth_offset;
        case DLT_PPP_SERIAL:
        case DLT_C_HDLC:
            auto chdlc = (struct ndpi_chdlc*) &packet[eth_offset];
            *type = ntohs(chdlc->proto_code);
            return sizeof(struct ndpi_chdlc);
        case DLT_LINUX_SLL:
            *type = (packet[eth_offset+14] << 8) + packet[eth_offset+15];
            return 16 + eth_offset;
        case DLT_RAW:
            return 0;
        case DLT_EN10MB:
            return get_uppper_layer_protocol_en(eth_offset, packet, type);
        case DLT_IEEE802_11_RADIO:
            return get_upper_layer_protocol_wlan(eth_offset, packet, type);
        default:
            return -1;
        }
    }

    int parse_header(int datalink_type, const struct pcap_pkthdr * header, const u_char *packet, struct ndpi_iphdr *ip_header, struct ndpi_ipv6hdr *ipv6_header)
    {
        u_int16_t eth_offset = 0, ip_offset, ip_len;
        u_int16_t type;

        struct ndpi_llc_header_snap * llc;
        struct ndpi_chdlc *chdlc;
        struct ndpi_ethhdr *ethernet;
        int check, pyld_eth_len = 0;

datalink_check:
        ip_offset = get_upper_layer_protocol(datalink_type, eth_offset, packet, &type);

        /* check ether type */
        if(type == VLAN) {
            vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
            type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
            ip_offset += 4;
            vlan_packet = 1;
        } else if(type == MPLS_UNI || type == MPLS_MULTI) {
            mpls = (struct ndpi_mpls_header *) &packet[ip_offset];
            label = ntohl(mpls->label);
            /* label = ntohl(*((u_int32_t*)&packet[ip_offset])); */
            type = ETH_P_IP, ip_offset += 4;
        
            while((label & 0x100) != 0x100) {
                ip_offset += 4;
                label = ntohl(mpls->label);
            }
        } else if(type == SLARP) {
            slarp = (struct ndpi_slarp *) &packet[ip_offset];
            if(slarp->slarp_type == 0x02 || slarp->slarp_type == 0x00 || slarp->slarp_type == 0x01) {
                /* TODO if info are needed */
            }
            slarp_pkts++;
        } else if(type == CISCO_D_PROTO) {
            cdp = (struct ndpi_cdp *) &packet[ip_offset];
            cdp_pkts++;
        } else if(type == PPPoE) {
            type = ETH_P_IP;
            ip_offset += 8;
        }


        iph_check:
        /* Check and set IP header size and total packet length */
        iph = (struct ndpi_iphdr *) &packet[ip_offset];
    
        /* just work on Ethernet packets that contain IP */
        if(type == ETH_P_IP && header->caplen >= ip_offset) {
            frag_off = ntohs(iph->frag_off);
        
            proto = iph->protocol;
            if(header->caplen < header->len) {
                static u_int8_t cap_warning_used = 0;
            
                if(cap_warning_used == 0) {
                    output(LOG_WARNING, "%s\n", "[WARN] packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY");
                    cap_warning_used = 1;
                }
            }
        }
    
        if(iph->version == 4) {
            ip_len = ((u_short)iph->ihl * 4);
            iph6 = NULL;
        
            if(iph->protocol == 41) {
                ip_offset += ip_len;
                goto iph_check;
            }
        
            if((frag_off & 0x3FFF) != 0) {
                static u_int8_t ipv4_frags_warning_used = 0;
                if(ipv4_frags_warning_used == 0) {
                    output(LOG_WARNING, "%s\n", "[WARN] IPv4 fragments has not been supported yet");
                    ipv4_frags_warning_used = 1;
                }
                return;
            }
        } else if(iph->version == 6) {
            iph6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
            proto = iph6->ip6_hdr.ip6_un1_nxt;
            ip_len = sizeof(struct ndpi_ipv6hdr);
        
            if(proto == 0x3C /* IPv6 destination option */) {
            
                u_int8_t *options = (u_int8_t*)&packet[ip_offset+ip_len];
                proto = options[0];
                ip_len += 8 * (options[1] + 1);
            }
            iph = NULL;
        
        } else {
            static u_int8_t ipv4_warning_used = 0;
        
        v4_warning:
            if(ipv4_warning_used == 0) {
                if(!quiet_mode)
                output(LOG_WARNING, "%s\n", "[WARN] only IPv4/IPv6 packets are supported by ndff, all other packets will be discarded");
                ipv4_warning_used = 1;
            }
            return;
        }
    }
}