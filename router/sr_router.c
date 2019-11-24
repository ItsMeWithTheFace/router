/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*Helper Functions*/
/*---------------------------------------------------------------------
 * Method: longest_prefix_match(struct sr_rt)
 * Scope:  Global
 *
 * Gets the longest prefix match of a given ip using the routing table
 *
 *---------------------------------------------------------------------*/

 struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t destination_ip)
 {
    struct sr_rt* best_match = 0;
    uint32_t current_ip_match = 0;

    struct sr_rt* walker = sr->routing_table;
    while(walker != NULL){
      if((walker->mask.s_addr & walker->dest.s_addr) == (walker->mask.s_addr & destination_ip)){
        if(!best_match || (walker->mask.s_addr > current_ip_match)){
          best_match = walker;
          current_ip_match = walker->mask.s_addr;
        }
      }
      walker = walker->next;
    }

    return best_match;
 }

  int forward_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len)
  {
    if (check_validity(packet, len, ethertype(packet)) != 0) return HOST_UNR;

    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    if (ip_header->ip_ttl <= 1) return 11;

    ip_header->ip_ttl -= 1;

    struct sr_rt* match = longest_prefix_match(sr, ip_header->ip_dst);

    return 0;
  }

  void new_ip_hdr(sr_ip_hdr_t* dest_ip_hdr, sr_ip_hdr_t* src_ip_hdr)
  {
    /* IP header */
    
    dest_ip_hdr->ip_hl = HL_IP;
    dest_ip_hdr->ip_v = V_IP;
    dest_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    dest_ip_hdr->ip_id = src_ip_hdr->ip_id;
    dest_ip_hdr->ip_tos = src_ip_hdr->ip_tos;
    dest_ip_hdr->ip_ttl = TTL_IP;
    dest_ip_hdr->ip_p = htons(ip_protocol_icmp);
    dest_ip_hdr->ip_sum = CHKSUM;
    dest_ip_hdr->ip_sum = cksum(CHKSUM, sizeof(sr_ip_hdr_t));
    dest_ip_hdr->ip_off = htons(IP_DF);
    dest_ip_hdr->ip_dst = src_ip_hdr->ip_src;
  }

  void new_eth_hdr(sr_ethernet_hdr_t* dest_eth_hdr, sr_ethernet_hdr_t* src_eth_hdr, struct sr_rt* match)
  {
    /* Ethernet header */
    dest_eth_hdr->ether_type = htons(ethertype_ip);
    memcpy(dest_eth_hdr->ether_shost, src_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(dest_eth_hdr->ether_dhost, match->interface, ETHER_ADDR_LEN);
  }

 void icmp_non_type0_handler(struct sr_instance* sr, sr_ip_hdr_t* src_ip_hdr, sr_ethernet_hdr_t* src_eth_hdr, int error_code_or_type)
 { 
    struct sr_rt *match = longest_prefix_match(sr, src_ip_hdr->ip_src);
    if(!match){
        fprintf(stderr,"Net Unreachable\n");
        return;
    }
    /* IP header */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*) malloc(sizeof(sr_ip_hdr_t));
    new_ip_hdr(ip_header, src_ip_hdr);

    /* Ethernet header */
    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t*) malloc(sizeof(sr_ethernet_hdr_t));
    new_eth_hdr(eth_header, src_eth_hdr, match);

    /* ICMP header */
    sr_icmp_t3_hdr_t *icmp_header = malloc(sizeof(sr_icmp_t3_hdr_t) + htons(src_ip_hdr->ip_len));

    /* Check error code or type */
    switch(error_code_or_type) 
    {
      case HOST_UNR:
        fprintf(stderr, "Host Unreachable");
        icmp_header->icmp_type = 3;
        icmp_header->icmp_code = HOST_UNR;
        break;
      case NET_UNR:
        fprintf(stderr, "Net Unreachable");
        icmp_header->icmp_type = 3;
        icmp_header->icmp_code = NET_UNR;
        break;
      case PORT_UNR:
        fprintf(stderr, "Port Unreachable");
        icmp_header->icmp_type = 3;
        icmp_header->icmp_code = PORT_UNR;
        break;
      case ICMP_TTL:
        fprintf(stderr, "TTL Exceeded");
        icmp_header->icmp_type = ICMP_TTL;
        icmp_header->icmp_code = 0;
        break;
      default:
        fprintf(stderr, "Code or Type doesn't exist");
        break;
    }

    icmp_header->unused = 0;
    uint8_t content = sizeof(sr_icmp_t3_hdr_t) + htons(src_ip_hdr->ip_len); 
    memcpy((uint8_t*)icmp_header + sizeof(sr_icmp_t3_hdr_t), &content, htons(src_ip_hdr->ip_len));
    icmp_header->icmp_sum = CHKSUM;
    icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t) + htons(src_ip_hdr->ip_len));

    struct sr_if* iface = sr_get_interface(sr, match->interface);

    if(icmp_header->icmp_code == PORT_UNR){
      ip_header->ip_src = src_ip_hdr->ip_dst;
    }else{
      ip_header->ip_src = iface->ip;
    }

    uint32_t length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t) + htons(src_ip_hdr->ip_len);
    uint8_t* buffer = malloc(length);
    memcpy(buffer, eth_header, sizeof(sr_ethernet_hdr_t));
    memcpy(buffer + sizeof(sr_ethernet_hdr_t), ip_header, sizeof(sr_ip_hdr_t));
    memcpy(buffer + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_header, sizeof(sr_icmp_t3_hdr_t) + htons(src_ip_hdr->ip_len));

    nexthop_interface(sr, buffer,  sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), match->gw.s_addr, iface);
    free(buffer);
 }

 void icmp_echo_handler(struct sr_instance* sr, sr_ip_hdr_t* src_ip_hdr, sr_ethernet_hdr_t* src_eth_hdr)
 { 
    uint8_t* buffer = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + ntohs(src_ip_hdr->ip_len));

    /* IP header */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*)(buffer + sizeof(sr_ethernet_hdr_t));
    memcpy(ip_header, src_ip_hdr, ntohs(src_ip_hdr->ip_len));
    ip_header->ip_dst = src_ip_hdr->ip_src;
    ip_header->ip_src = src_ip_hdr->ip_dst;
    ip_header->ip_sum = cksum(buffer+sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));

    struct sr_rt *match = longest_prefix_match(sr, src_ip_hdr->ip_src);
    if(!match){
        fprintf(stderr,"Net Unreachable\n");
        free(buffer);
        return;
    }

    struct sr_if* iface = sr_get_interface(sr, match->interface);

    /* Ethernet header */
    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t*)buffer;
    eth_header->ether_type = htons(ethertype_ip);
    memset(eth_header->ether_shost,0x00,ETHER_ADDR_LEN);
    memset(eth_header->ether_dhost,0x00,ETHER_ADDR_LEN);

    /* ICMP header */
    sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t*)(buffer + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_header->icmp_type = 0;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_sum  = 0;
    icmp_header->icmp_sum = CHKSUM;
    icmp_header->icmp_sum = cksum((uint8_t*)icmp_header, ntohs(src_ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
    

    nexthop_interface(sr, buffer, sizeof(sr_ethernet_hdr_t) + ntohs(src_ip_hdr->ip_len),match->gw.s_addr, iface);
    free(buffer);
 }


 int check_validity(uint8_t * packet, unsigned int len, uint16_t packet_type)
 {
   unsigned int minimum_len = sizeof(sr_ethernet_hdr_t);
   if(len < minimum_len){
     fprintf(stderr, "Ethernet Header Length Too Short\n");
     return 1;
   }
   
   sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t*)packet;

   if(packet_type == ethertype_ip){
     minimum_len += sizeof(sr_ip_hdr_t);

     if (len < minimum_len){
       fprintf(stderr, "IP Header Length Too Short\n");
       return 2;
     }

     sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
     if(ip_header->ip_hl < 5 || ip_header->ip_v != 4){
       fprintf(stderr, "Wrong Packet Version\n");
       return 3;
     }
     
     uint32_t curr_ip_sum = ip_header->ip_sum;
     ip_header->ip_sum = CHKSUM;
     if(cksum(ip_header, ip_header->ip_hl*4) != curr_ip_sum){
       fprintf(stderr,"IP Checksum Mismatch");
       return 4;
     }

     if(ip_header->ip_p == ip_protocol_icmp) {
       minimum_len += sizeof(sr_icmp_hdr_t);
       if(len < minimum_len){
         fprintf(stderr, "ICMP Header Length Too Short\n");
         return 5;
       }

       sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
       uint32_t curr_icmp_sum = icmp_header->icmp_sum;
       icmp_header->icmp_sum = CHKSUM;
       if(cksum((uint8_t*)icmp_header, ntohs(ip_header->ip_len) - sizeof(sr_ip_hdr_t)) != curr_icmp_sum){
         fprintf(stderr, "ICMP Checksum Mismatch\n");
         return 6;
       }
     }
   }else if(packet_type == ethertype_arp){
     minimum_len += sizeof(sr_arp_hdr_t);
     if(len < minimum_len){
       fprintf(stderr, "ARP Header Length Too Short\n");
       return 7;
     }
   } else{
     fprintf(stderr, "Unknown Ethernet Type");
     return 8;
   }

   return 0;
 }

 void nexthop_interface(struct sr_instance* sr, uint8_t* packet, unsigned int length, uint32_t ip, struct sr_if* iface)
 {
   struct sr_arpentry* entry = sr_arpcache_lookup(&(sr->cache), ip);

   if(entry != NULL){
     sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*)(packet);
     memcpy(eth_header->ether_dhost,entry->mac,ETHER_ADDR_LEN);
     memcpy(eth_header->ether_shost,iface->addr,ETHER_ADDR_LEN);
     sr_send_packet(sr,packet,length,iface->name);
     free(entry);
   }else{
     struct sr_arpreq *request = sr_arpcache_queuereq(&sr->cache, ip, packet, length, iface->name);
     handle_arpreq(sr, request);
   }
 }

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  uint16_t packet_type = ethertype(packet);

  if (check_validity(packet, len, packet_type) != 0) {
    fprintf(stderr, "oof\n");
    return;
  }

  sr_ethernet_hdr_t * eth_header = (sr_ethernet_hdr_t *) packet;

  if (packet_type == ethertype_ip) {
    /* Incoming IP packet */
    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ip_hdr_t));
    struct sr_if* if_walker = 0;
    if_walker = sr->if_list;

    while(if_walker != NULL) {      
      /* check if request is to me */
      if (if_walker->ip == ip_header->ip_dst) {
        /* check if request ICMP echo */
        if (ip_header->ip_p == ip_protocol_icmp) {
          sr_icmp_hdr_t * icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          if (icmp_header->icmp_type == 0) { /* echo request */
            icmp_echo_handler(
              sr,
              (sr_ip_hdr_t *) (packet + sizeof(sr_ip_hdr_t)),
              (sr_ethernet_hdr_t *) packet
            );
          }
        } else { /* TCP/UDP request */
          icmp_non_type0_handler(
            sr,
            (sr_ip_hdr_t *) (packet + sizeof(sr_ip_hdr_t)),
            (sr_ethernet_hdr_t *) packet,
            PORT_UNR
          );
        }
        return;
      }
      if_walker = if_walker->next;
    }
    /* packet is not destined to me */
    int error = forward_packet(sr, packet, len);
    if (error != 0) {
      icmp_non_type0_handler(
            sr,
            (sr_ip_hdr_t *) (packet + sizeof(sr_ip_hdr_t)),
            (sr_ethernet_hdr_t *) packet,
            error
          );
    }
  } else if (packet_type == ethertype_arp) {
    
  }


}/* end sr_ForwardPacket */

