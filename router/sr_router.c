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
    while(walker != NULL) {
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

 void icmp_non_type0_handler(struct sr_instance* sr, sr_ip_hdr_t* src_ip_hdr, sr_ethernet_hdr_t* src_eth_hdr, int error_code_or_type)
 { 	
    printf("ICMP\n");
    uint8_t* buffer = (uint8_t*) malloc(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));

    /* Ethernet header */
    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t*)(buffer);
    eth_header->ether_type = htons(ethertype_ip);
    memset(eth_header->ether_shost, 0, ETHER_ADDR_LEN);
    memset(eth_header->ether_dhost, 0, ETHER_ADDR_LEN);
    /* IP header */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*)(buffer + sizeof(sr_ethernet_hdr_t));
    ip_header->ip_hl = HL_IP;
    ip_header->ip_v = V_IP;
    ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ip_header->ip_id = src_ip_hdr->ip_id;
    ip_header->ip_tos = src_ip_hdr->ip_tos;
    ip_header->ip_ttl = TTL_IP;
    ip_header->ip_p = htons(ip_protocol_icmp);
    ip_header->ip_sum = CHKSUM;
    ip_header->ip_sum = cksum((uint8_t*)ip_header, sizeof(sr_ip_hdr_t));
    ip_header->ip_off = htons(IP_DF);
    ip_header->ip_dst = src_ip_hdr->ip_src;

    struct sr_rt *match = longest_prefix_match(sr, src_ip_hdr->ip_src);
    if(!match){
        printf("Error\n");
        free(buffer);
        return;
    }

    struct sr_if* iface = sr_get_interface(sr, match->interface);
    
    /* ICMP header */
    sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t *)((uint8_t*)ip_header + sizeof(sr_ip_hdr_t));
    /* Check error code or type */
    switch(error_code_or_type) 
    {
      case HOST_UNR:
        fprintf(stderr, "Host Unreachable\n");
        icmp_header->icmp_type = 3;
        icmp_header->icmp_code = HOST_UNR;
        break;
      case NET_UNR:
        fprintf(stderr, "Net Unreachable\n");
        icmp_header->icmp_type = 3;
        icmp_header->icmp_code = NET_UNR;
        break;
      case PORT_UNR:
        fprintf(stderr, "Port Unreachable\n");
        icmp_header->icmp_type = 3;
        icmp_header->icmp_code = PORT_UNR;
        break;
      case ICMP_TTL:
        fprintf(stderr, "TTL Exceeded\n");
        icmp_header->icmp_type = ICMP_TTL;
        icmp_header->icmp_code = 0;
        break;
      default:
        fprintf(stderr, "Code or Type doesn't exist\n");
        break;
    }

    icmp_header->icmp_sum = CHKSUM;
    memcpy(icmp_header->data, src_ip_hdr, ICMP_DATA_SIZE);
    icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));

    print_hdr_icmp((uint8_t*)ip_header + sizeof(sr_ip_hdr_t));
    if(icmp_header->icmp_code == PORT_UNR) {
      ip_header->ip_src = src_ip_hdr->ip_dst;
    } else {
      ip_header->ip_src = iface->ip;
    }
    nexthop_interface(sr, buffer,  sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), match->gw.s_addr, iface);
    free(buffer);
 }

 void icmp_echo_handler(struct sr_instance* sr, sr_ip_hdr_t* src_ip_hdr, sr_ethernet_hdr_t* src_eth_hdr)
 { 
    uint8_t* buffer = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + ntohs(src_ip_hdr->ip_len));

    /* Ethernet header */
    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t*) buffer;
    eth_header->ether_type = htons(ethertype_ip);
    memset(eth_header->ether_shost, 0x00, ETHER_ADDR_LEN);
    memset(eth_header->ether_dhost, 0x00, ETHER_ADDR_LEN);

    /* IP header */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*)(buffer + sizeof(sr_ethernet_hdr_t));
    memcpy(ip_header, src_ip_hdr, ntohs(src_ip_hdr->ip_len));
    ip_header->ip_dst = src_ip_hdr->ip_src;
    ip_header->ip_src = src_ip_hdr->ip_dst;
    ip_header->ip_sum = cksum(buffer+sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));

    struct sr_rt *match = longest_prefix_match(sr, src_ip_hdr->ip_src);
    if(!match) {
        fprintf(stderr, "Net Unreachable\n");
        free(buffer);
        return;
    }

    struct sr_if* iface = sr_get_interface(sr, match->interface);

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

   if(packet_type == ethertype_ip){
     minimum_len += sizeof(sr_ip_hdr_t);

     if (len < minimum_len){
       fprintf(stderr, "IP Header Length Too Short\n");
       return 2;
     }

     sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
     if(ip_header->ip_hl < HL_IP || ip_header->ip_v != V_IP){
       fprintf(stderr, "Wrong Packet Version\n");
       return 3;
     }
     
     uint32_t curr_ip_sum = ip_header->ip_sum;
     ip_header->ip_sum = CHKSUM;
     if(cksum(ip_header, ip_header->ip_hl * 4) != curr_ip_sum){
       fprintf(stderr,"IP Checksum Mismatch");
       ip_header->ip_sum = curr_ip_sum;
       return 4;
     }

     if(ip_header->ip_p == ip_protocol_icmp) {
       minimum_len += sizeof(sr_icmp_hdr_t);
       if(len < minimum_len){
         fprintf(stderr, "ICMP Header Length Too Short\n");
         return 5;
       }

       sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
       uint32_t curr_icmp_sum = icmp_header->icmp_sum;
       icmp_header->icmp_sum = CHKSUM;
       if(cksum((uint8_t *) icmp_header, ntohs(ip_header->ip_len) - sizeof(sr_ip_hdr_t)) != curr_icmp_sum){
         fprintf(stderr, "ICMP Checksum Mismatch\n");
         icmp_header->icmp_sum = curr_icmp_sum;
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
     sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t *)(packet);
     memcpy(eth_header->ether_dhost,entry->mac,ETHER_ADDR_LEN);
     memcpy(eth_header->ether_shost,iface->addr,ETHER_ADDR_LEN);
     sr_send_packet(sr,packet,length,iface->name);
     free(entry);
   } else {
     sr_arpcache_queuereq(&sr->cache, ip, packet, length, iface->name);
   }
 }

 int check_destination(struct sr_instance* sr, uint32_t ip_dst){
   struct sr_if* iface_walker = sr->if_list;

   while(iface_walker != NULL){
     if(ip_dst == iface_walker->ip){
       return 1;
     }

     iface_walker = iface_walker->next;
   }

   return 0;
 }

  int arp_check(sr_arp_hdr_t* arp_header){
    if(ntohs(arp_header->ar_hrd)==arp_hrd_ethernet && ntohs(arp_header->ar_pro) == ethertype_ip && arp_header->ar_hln == ETHER_ADDR_LEN && arp_header->ar_pln == 4){
      return 1;
    }else{
      return 0;
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

    printf("*** -> GOT IP with Header Length: %d \n",len);
    /* Incoming IP packet */
    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    print_hdr_ip((packet + sizeof(sr_ethernet_hdr_t)));
    int checker = check_destination(sr, ip_header->ip_dst);

    /* Destination is us */
    if(checker == 1){
      printf("CHECKER SUCCESS \n");
      if(ip_header->ip_p == 1){
        printf("Echo Requested \n");
        icmp_echo_handler(sr, ip_header, eth_header);
      }else{
        printf("None Type0\n");
        icmp_non_type0_handler(sr, ip_header, eth_header, PORT_UNR);
      }

    } else {
      printf("CHECKER FAIL \n");
      if (ip_header->ip_ttl <= 1){
        icmp_non_type0_handler(sr, ip_header, eth_header, ICMP_TTL);
      }
      ip_header->ip_ttl = ip_header->ip_ttl-1;
      ip_header->ip_sum = 0;
      ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl*4);
      printf("	TTL = %d\n",ip_header->ip_ttl);
      struct sr_rt *match = longest_prefix_match(sr, ip_header->ip_dst);
      if(!match) {
        printf("	no match in LPM, net unreachable\n");
        icmp_non_type0_handler(sr, ip_header, eth_header, NET_UNR);
      } else {
        printf("MATCH FOUND\n");
        struct sr_if *iface = sr_get_interface(sr, match->interface);
        nexthop_interface(sr, packet, len, match->gw.s_addr,iface);
      }
    }
  } else if (packet_type == ethertype_arp) {
    printf("*** -> ARP %d \n",len);

    sr_arp_hdr_t * arp_src = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    int arp_valid = arp_check(arp_src);
    struct sr_if* iface = sr_get_interface(sr, interface);
    if(arp_valid == 1) {
      if(ntohs(arp_src->ar_op) == arp_op_request) {
        if(arp_src->ar_tip == iface->ip) {
          uint8_t* buffer = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
          assert(buffer);

          sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*)(buffer);
          memcpy(eth_header->ether_dhost, arp_src->ar_sha, ETHER_ADDR_LEN);
          memcpy(eth_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
          eth_header->ether_type = htons(ethertype_arp);
          sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(buffer + sizeof(sr_ethernet_hdr_t));
          arp_header->ar_hrd = htons(arp_hrd_ethernet);
          arp_header->ar_pro = htons(ethertype_ip);
          arp_header->ar_hln = ETHER_ADDR_LEN;
          arp_header->ar_pln = 4;
          arp_header->ar_op = htons(arp_op_reply);
          memcpy(arp_header->ar_sha, iface->addr, ETHER_ADDR_LEN);
          arp_header->ar_sip = iface->ip;
          memcpy(arp_header->ar_tha, arp_src->ar_sha, ETHER_ADDR_LEN);
          arp_header->ar_tip = arp_src->ar_sip;
          sr_send_packet(sr, buffer,sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), iface->name);
          free(buffer);
        } else {
          fprintf(stderr,"Error\n");
          return;
        }
      } else if(ntohs(arp_src->ar_op) == arp_op_reply) {
        if(arp_src->ar_tip == iface->ip) {
          struct sr_arpreq* request = sr_arpcache_insert(&sr->cache, arp_src->ar_sha, arp_src->ar_sip);
          
          if(request != NULL) {
            struct sr_if* iface;
            struct sr_packet* curr_pkt = request->packets;
            while(curr_pkt != NULL) {
              iface = sr_get_interface(sr, curr_pkt->iface);
              nexthop_interface(sr,curr_pkt->buf, curr_pkt->len, request->ip, iface);
              curr_pkt = curr_pkt->next;
            }

            sr_arpreq_destroy(&(sr->cache), request);
          }
        } else {
          fprintf(stderr, "No ARP Request recieved\n");
          return;
        }
      }
    }
  } else {
    fprintf(stderr, "Packet could not be handled\n");
    return;
  }
}/* end sr_ForwardPacket */

