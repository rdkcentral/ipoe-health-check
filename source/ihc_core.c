/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 Sky
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**************** System header files ***************************/
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <sysevent/sysevent.h>
#include "ihc_main.h"

/**************** Defines ***************************************/
#define IHC_LOOP_TIMOUT 1
#define TRUE 1
#define IHC_ECHO_REPLY_TIME_OUT 5
#define IHC_LOCK_TIMEOUT ( 2 * MSECS_IN_SEC )
#define IHC_MAX_STRING_LENGTH 256
/* Packet constrcution related MACROS */
#define IHC_MACADDR_LEN 6
#define IHC_MACADDR_STR_LEN 29  // mac address format(0xHH:0xHH:0xHH:0xHH:0xHH:0xHH)
#define IHC_ETHTYPE_LEN 2
#define IHC_UDP_HDRLEN 8
#define IHC_ETH_HDRLEN 14
#define IHC_IP_HDRLEN 5
#define IHC_IP_HDR_VERSION 4
#define IHC_IP_HDR_TOS 16
#define IHC_IP_HDR_ID 54321
#define IHC_IP_HDR_TTL 255
#define IHC_IP6_HDRLEN 40
#define IHC_PRIORITY_MARKING 0x100007 //7 is our high priority queue on WAN side 
#define IHC_MAX_UDP_PACKET_LENGTH 512
#define IHC_DESTINATION_PORT 3785
#define IHC_SOURCE_PORT 49153
/* Checksum related MACROS */
#define CSUM_16_BIT_SHIFT 16
#define CSUM_16_BIT_MASK  0xffff
#define IS_EMPTY_STRING(s)    ((s == NULL) || (*s == '\0'))
#define IHC_STRIP_LAST_CHAR_INDEX 2
#define NANOSEC2SEC       1000000000.0
#define IPOE_HEALTH_CHECK_V4_STATUS "ipoe_health_check_ipv4_status"
#define IPOE_HEALTH_CHECK_V6_STATUS "ipoe_health_check_ipv6_status"
#define IPOE_STATUS_SUCCESS "success"
#define IPOE_STATUS_FAILED "failed"
#define SYS_IP_ADDR    "127.0.0.1"

/**************** Global Variables ******************************/
static int g_send_V4_echo = 0;
static int g_send_V6_echo = 0;
static int g_echo_V4_failure_count = 0;
static int g_echo_V6_failure_count = 0;
static int g_echo_V4_success_count = 0;
static int g_echo_V6_success_count = 0;

static UBOOL8 g_v4_connection = FALSE;
static UBOOL8 g_v6_connection = FALSE;
static UBOOL8 v4_startup_sequence_completed = FALSE;
static UBOOL8 v6_startup_sequence_completed = FALSE;
static UBOOL8 wan_v4_release = FALSE;
static UBOOL8 wan_v6_release = FALSE;
static UBOOL8 Is_v4_bfd_1stpkt_failure_occurs = FALSE;
static UBOOL8 Is_v6_bfd_1stpkt_failure_occurs = FALSE;
static UBOOL8 Is_v4_bfd_1stpkt_success_occurs = FALSE;
static UBOOL8 Is_v6_bfd_1stpkt_success_occurs = FALSE;

static ipc_ihc_data_t wanConnectionData;
static int sysevent_fd = -1;
static token_t sysevent_token;
/**************** Extern variables ******************************/

extern int   ipcListenFd;

/***************** Function defenitions *************************/

/**
 * @brief Function to validate the given mac address
 *
 * @param mac address of the router
 * @return IHC_SUCCESS / IHC_FAILURE
 */
static int validateMacAddr(const char * mac)
{
    int ret = IHC_FAILURE;
    uint32_t bytes[IHC_MACADDR_LEN]={0};
    // mac address format(0xHH:0xHH:0xHH:0xHH:0xHH:0xHH)
    if( NULL == mac || strlen(mac) != IHC_MACADDR_STR_LEN )
    {
         IhcError("[%s:%d] Invalid args mac[%s]", __FUNCTION__, __LINE__,(NULL == mac)?"NULL":mac);
         return ret;
    }
    if( IHC_MACADDR_LEN == sscanf(mac, "%04X:%04X:%04X:%04X:%04X:%04X",
            &bytes[5], &bytes[4], &bytes[3], &bytes[2], &bytes[1], &bytes[0]))
    {
         ret = IHC_SUCCESS;
    }
    return ret;
}

/**
 * @brief Function to get the global deligated prefix
 * 
 * @param globalAddress global address pf the router
 * @return IHC_SUCCESS / failure 
 */
static int ihc_get_ipv6_global_address(char *globalAddress, size_t globalAddressLen)
{
    int ret = IHC_SUCCESS;
    char ipv6PrefixAddr [IHC_MAX_STRING_LENGTH] = {0};

    if (globalAddress == NULL || globalAddressLen == 0)
    {
        IhcError("[%s:%d] Invalid args.. ", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    if(IS_EMPTY_STRING(wanConnectionData.ipv6Address))
    {
        IhcError("[%s:%d] Failed to get the global IPv6 address \n", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    strncpy(ipv6PrefixAddr, wanConnectionData.ipv6Address, sizeof(ipv6PrefixAddr));

    if (!IS_EMPTY_STRING(ipv6PrefixAddr))
    {
        char *token = strtok(ipv6PrefixAddr, "/");
        if(token)
        {
            strncpy(globalAddress, token, globalAddressLen);
        }
        else
        {
            IhcError("[%s:%d] Could not get valid address\n", __FUNCTION__, __LINE__);
            ret = IHC_FAILURE;
        }
    }
    else
    {
        IhcError("[%s:%d] Ignore the empty Dhcpv6 prefix\n", __FUNCTION__, __LINE__);            
        ret = IHC_FAILURE;
    }
   
    IhcInfo("[%s:%d] Global address returning as [%s]",__FUNCTION__, __LINE__, globalAddress);
    return ret;
}

/**
 * @brief get the BNG MAC address from neighbor discovery
 * 
 * @param ipAddress Link local address of BNG
 * @param MACAddress  BNG mac address
 * @return int IHC_SUCCESS on success / IHC_FAILURE on failure
 */
static int ihc_get_V6_bng_MAC_address(char *ipAddress, char *MACAddress, unsigned int len)
{
    char command[IHC_MAX_STRING_LENGTH] = {0};
    char line[IHC_MAX_STRING_LENGTH] = {0};
    FILE *fp;
    int ret = IHC_FAILURE;

    if (ipAddress == NULL || MACAddress == NULL || len == 0)
    {
        IhcError("[%s %d]Ivalid args\n", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    if( strlen(ipAddress) > 0 )
    {
        snprintf(command, IHC_MAX_STRING_LENGTH, "ip -6 neighbor show | grep -w %s | awk '{print $5}'", ipAddress);

        fp = popen(command, "r");

        if (fp)
        {
            if (fgets(line, sizeof(line), fp) != NULL)
            {
                //Convert into proper format
                char *token = strtok(line, ":");
                while (token)
                {
                    char tmpString[IHC_MAX_STRING_LENGTH] = {0};
                    snprintf(tmpString, IHC_MAX_STRING_LENGTH, "0x%s:", token);
                    strncat(MACAddress, tmpString, len - strlen(MACAddress) - 1);
                    token = strtok(NULL, ":");
                }

                if (strlen(MACAddress) > 0 && strstr(MACAddress, ":" ))
                {
                    MACAddress[strlen(MACAddress) - IHC_STRIP_LAST_CHAR_INDEX] = '\0'; //strip of last "\n:"
                    // return success only if we have a valid mac
                    ret = validateMacAddr(MACAddress);
                }
            }
            pclose(fp);
        }
    }

    return ret;
}

/**
 * @brief get the BNG MAC address from arp
 * 
 * @param ipAddress global ip address of router
 * @param MACAddress  BNG mac address
 * @return int IHC_SUCCESS on success / IHC_FAILURE on failure
 */
static int ihc_get_V4_bng_MAC_address(char *ipAddress, char *MACAddress, unsigned int len)
{
    char command[IHC_MAX_STRING_LENGTH] = {0};
    char line[IHC_MAX_STRING_LENGTH] = {0};
    FILE *fp;
    int ret = IHC_FAILURE;

    if (ipAddress == NULL || MACAddress == NULL || len == 0)
    {
        IhcError("[%s: %d] Invalid args..", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    if( strlen(ipAddress) > 0 )
    {
        memset(command, 0, IHC_MAX_STRING_LENGTH);
        snprintf(command, IHC_MAX_STRING_LENGTH, "arp -an| grep %s | awk '{print $4}'", ipAddress);

        fp = popen(command, "r");

        if (fp)
        {
            if (fgets(line, sizeof(line), fp) != NULL)
            {
                //Convert into proper format
                char *token = strtok(line, ":");
                while (token)
                {
                    char tmpString[IHC_MAX_STRING_LENGTH] = {0};
                    snprintf(tmpString, IHC_MAX_STRING_LENGTH, "0x%s:", token);
                    strncat(MACAddress, tmpString, len - strlen(MACAddress) - 1);
                    token = strtok(NULL, ":");
                }
                
                if (strlen(MACAddress) > 0 && strstr(MACAddress, ":"))
                {
                    MACAddress[strlen(MACAddress) - IHC_STRIP_LAST_CHAR_INDEX] = '\0'; //strip of last "\n:"
                    // return success only if we have a valid gateway mac in arp cache
                    ret = validateMacAddr(MACAddress);
                }
                IhcInfo("[%s: %d] BNG MAC: %s", __FUNCTION__, __LINE__, MACAddress);
            }
            pclose(fp);
        }
    }

    return ret;
}

/**
 * @brief To get the default gateway and wan interface name (v6)
 * 
 * @param interface (OUT) WAN interface name
 * @param defaGateway (OUT) Default gateway IP address
 * @return IHC_SUCCESS/ IHC_FAILURE
 */
static int ihc_get_V6_defgateway_wan_interface(char *interface, size_t interfaceLen, char *defGateway, size_t defGatewayLen)
{
    int ret = IHC_SUCCESS;

    if (interface == NULL || defGateway == NULL || interfaceLen == 0 || defGatewayLen == 0)
    {
        IhcError("[%s: %d] Invalid args..", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    if(g_v6_connection) //check ipv6 is up.
    {
        /* Get wan interface name. */
        if(IS_EMPTY_STRING(wanConnectionData.ifName))
        {
            IhcError("[%s: %d] invalid wan interface name: %s", __FUNCTION__, __LINE__, wanConnectionData.ifName);
            return IHC_FAILURE;
        }
        strncpy(interface, wanConnectionData.ifName, interfaceLen);

        /* Default IPv6 GW. */
        char command[IHC_MAX_STRING_LENGTH] = {0};
        char line[IHC_MAX_STRING_LENGTH] = {0};
        FILE *fp;

        snprintf(command, sizeof(command), "ip -6 route show default | grep default | awk '{print $3}'");

        fp = popen(command, "r");

        if (fp)
        {
            if (fgets(line, sizeof(line), fp) != NULL)
            {
                char *token = strtok(line, "\n"); // get string up until newline character
                if (token)
                {
                    strncpy(defGateway, token, defGatewayLen);
                    IhcInfo("IPv6 Default GW address  = %s", defGateway);
                }
                else
                {
                    IhcError("[%s: %d] Could not parse ipv6 gw addr", __FUNCTION__, __LINE__);
                    ret = IHC_FAILURE;
                }
            }
            else
            {
                IhcError("[%s: %d] Could not read ipv6 gw addr", __FUNCTION__, __LINE__);
                ret = IHC_FAILURE;
            }
            pclose(fp);
        }
        else
        {
            IhcError("[%s: %d] Failed to get the default gw address", __FUNCTION__, __LINE__);
            ret = IHC_FAILURE;
        }
    }

    return ret;
}

/**
 * @brief To get the default gateway and wan interface name(V4)
 * 
 * @param interface (OUT) WAN interface name
 * @param defaGateway (OUT) Default gateway IP address
 * @return IHC_SUCCESS/ IHC_FAILURE
 */
static int ihc_get_V4_defgateway_wan_interface(char *interface, size_t interfaceLen, char *defGateway, size_t defGatewayLen)
{
    int ret = IHC_SUCCESS;

    if (interface == NULL || defGateway == NULL || interfaceLen == 0 || defGatewayLen == 0)
    {
        IhcError("[%s: %d] Invalid args..", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    if(g_v4_connection)
    {
        /* Get wan interface name. */
        if(IS_EMPTY_STRING(wanConnectionData.ifName))
        {
            IhcError("[%s: %d] invalid wan interface name :%s", __FUNCTION__, __LINE__, wanConnectionData.ifName);
            return IHC_FAILURE;
        }
        strncpy(interface, wanConnectionData.ifName, interfaceLen);
        IhcInfo("[%s: %d] WAN Physical Interface name = %s", __FUNCTION__, __LINE__, interface);

        /* Default IPv4 GW. */
        char command[IHC_MAX_STRING_LENGTH] = {0};
        char line[IHC_MAX_STRING_LENGTH] = {0};
        FILE *fp;

        snprintf(command, sizeof(command), "ip route show default | grep default | awk '{print $3}'");

        fp = popen(command, "r");

        if (fp)
        {
            if (fgets(line, sizeof(line), fp) != NULL)
            {
                char *token = strtok(line, "\n"); // get string up until newline character
                if (token)
                {
                    strncpy(defGateway, token, defGatewayLen);
                    IhcInfo("IPv4 Default GW address  = %s", defGateway);
                }
                else
                {
                    IhcError("[%s: %d] Could not parse ipv4 gw addr", __FUNCTION__, __LINE__);
                    ret = IHC_FAILURE;
                }
            }
            else
            {
                IhcError("[%s: %d] Could not read ipv4 gw addr", __FUNCTION__, __LINE__);
                ret = IHC_FAILURE;
            }
            pclose(fp);
        }
        else
        {
            IhcError("[%s: %d] Failed to get the default gateway address", __FUNCTION__, __LINE__);
            ret = IHC_FAILURE;
        }
    }

    return ret;
}

/**
 * @brief start sending echo packets
 * 
 * @param echoType  echo packet type V4/V6
 * @return int IHC_SUCCESS on success / IHC_FAILURE on failure
 */

static int ihc_start_echo_packets(eIHCEchoType echoType)
{
    char cmd[IHC_MAX_STRING_LENGTH] = {0};
    int ret = IHC_SUCCESS;

    switch (echoType)
    {
        case IHC_ECHO_TYPE_V4:
            if (g_send_V4_echo == 0)
            {
                snprintf(cmd, sizeof(cmd), "%s", "echo 1 > /proc/sys/net/ipv4/conf/all/accept_local");
                system(cmd);

                // Sending ping packet to BNG to resolve ARP,
                // sometimes MAC address of BNG is not resolved so triggering ARP resolution - happens only once
                memset(cmd, 0, IHC_MAX_STRING_LENGTH);
                snprintf(cmd, IHC_MAX_STRING_LENGTH, "ping -c 1 %s", wanConnectionData.ipv4Address);
                system(cmd);

                g_send_V4_echo = 1;
            }
            else
            {
                IhcError("[%s: %d] IHC already started for V4", __FUNCTION__, __LINE__);
                ret = IHC_FAILURE;
            }
            break;
        case IHC_ECHO_TYPE_V6:
            if (g_send_V6_echo == 0)
            {
                g_send_V6_echo = 1;
            }
            else
            {
                IhcError("[%s: %d] IHC already started for V6", __FUNCTION__, __LINE__);
                ret = IHC_FAILURE;
            }
            break;
        default:
            IhcError("[%s: %d] Unknown echo type value", __FUNCTION__, __LINE__);
            ret = IHC_FAILURE;
    }
    return ret;
}

/**
 * @brief stop sending echo packets
 * 
 * @param echoType echo packet type V4/V6
 * @return int IHC_SUCCESS on success / IHC_FAILURE on failure
 */

static int ihc_stop_echo_packets(eIHCEchoType echoType)
{
    char cmd[IHC_MAX_STRING_LENGTH] = {0};
    int ret = IHC_SUCCESS;

    switch (echoType)
    {
    case IHC_ECHO_TYPE_V4:
        snprintf(cmd, sizeof(cmd), "%s", "echo 0 > /proc/sys/net/ipv4/conf/all/accept_local");
        system(cmd);
        g_send_V4_echo = 0;
        g_v4_connection = FALSE;
        g_echo_V4_failure_count = 0;
        g_echo_V4_success_count = 0;
        v4_startup_sequence_completed = FALSE;
        break;
    case IHC_ECHO_TYPE_V6:
        g_send_V6_echo = 0;
        g_v6_connection = FALSE;
        g_echo_V6_failure_count = 0;
        g_echo_V6_success_count = 0;
        v6_startup_sequence_completed = FALSE;
        break;
    default:
        IhcError("[%s: %d] Unknown echo type value", __FUNCTION__, __LINE__);
        ret = IHC_FAILURE;
    }
    return ret;
}

/**
 * @brief Function to broadcast IHC events to the system
 * 
 * @param myEid EID of the process
 * @param msgHandle message handle
 * @param message actual message
 * @return int IHC_SUCCESS on success / IHC_FAILURE on failure
 */

static int ihc_broadcastEvent(int message)
{
    int sock = -1;
    int conn = -1;

    sock = nn_socket(AF_SP, NN_PUSH);
    if (sock < 0)
    {
        IhcError("[%s: %d] IHC: ihc_broadcastEvent failed", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    conn = nn_connect(sock, WAN_MANAGER_ADDR);
    if (conn < 0)
    {
        IhcError("[%s: %d] ihc_broadcastEvent: Failed to connect to the wanmanager socket", __FUNCTION__, __LINE__);
        nn_close (sock);
        return IHC_FAILURE;
    }

    // Preparing msg payload
    ipc_ihc_data_t msgBody;
    memset (&msgBody, 0, sizeof(ipc_ihc_data_t));
    msgBody.msgType = message;
    strncpy(msgBody.ifName, g_ifName, IFNAME_LENGTH - 1);

    // Preparing msg header and adding payload
    ipc_msg_payload_t msg;
    memset(&msg, 0, sizeof(ipc_msg_payload_t));
    msg.msg_type = IHC_STATE_CHANGE;
    memcpy(&msg.data.ihcData, &msgBody, sizeof(ipc_ihc_data_t));


    int bytes = 0;
    int msgSize = sizeof(ipc_msg_payload_t);

    bytes = nn_send(sock, (char *) &msg, msgSize, 0);
    if (bytes < 0)
    {
        IhcError("[%s-%d] Failed to send data to wanmanager  error=[%d][%s]", __FUNCTION__, __LINE__,errno, strerror(errno));
        nn_close (sock);
        return IHC_FAILURE;
    }

    IhcInfo("[%s-%d] Successfully send %d bytes to wanmanager", __FUNCTION__, __LINE__, bytes);
    nn_close (sock);
    return IHC_SUCCESS;

}

/**
 * @brief Function to calculate checksum
 * 
 * @param buf Packet data
 * @param nwords Packet data size
 * @return uint16_t Actual checksum based on packet data
 */
static uint16_t csum(uint16_t *buf, int nwords)
{
    uint32_t sum;

    if (buf == NULL)
    {
        IhcError("[%s: %d] Invalid args..", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    for (sum = 0; nwords > 0; nwords--)
    {
        sum += *buf++;
    }
    sum = (sum >> CSUM_16_BIT_SHIFT) + (sum & CSUM_16_BIT_MASK);
    sum += (sum >> CSUM_16_BIT_SHIFT);
    return (uint16_t)(~sum);
}

// Note that the internet checksum does not preclude collisions.
/**
 * @brief Data checksum calculations
 * 
 * @param addr Paylaod data
 * @param len payload length
 * @return uint16_t calculated checksum
 */

static uint16_t checksum(uint16_t *addr, int len)
{
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    if (addr == NULL)
    {
        IhcError("[%s: %d] Invalid args..", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1)
    {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0)
    {
        sum += *(uint8_t *)addr;
    }

    // Implementation based on RFC1071.
    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
    {
        sum = (sum & CSUM_16_BIT_MASK) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}

/**
 * @brief IPV6 UDP header checksum calculation functions
 * Build IPv6 UDP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
 * @param iphdr IPV6 header
 * @param udphdr UDP header
 * @param payload payload (IPV6 data)
 * @param payloadlen Payload length
 * @return uint16_t return checksum
 */

static uint16_t udp6_checksum(struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{
    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    if (payload == NULL)
    {
        IhcError("[%s %d] Invalid args...", __FUNCTION__, __LINE__);
        return 0;
    }

    ptr = &buf[0]; // ptr points to beginning of buffer buf

    // Copy source IP address into buf (128 bits)
    memcpy(ptr, &iphdr.ip6_src.s6_addr, sizeof(iphdr.ip6_src.s6_addr));
    ptr += sizeof(iphdr.ip6_src.s6_addr);
    chksumlen += sizeof(iphdr.ip6_src.s6_addr);

    // Copy destination IP address into buf (128 bits)
    memcpy(ptr, &iphdr.ip6_dst.s6_addr, sizeof(iphdr.ip6_dst.s6_addr));
    ptr += sizeof(iphdr.ip6_dst.s6_addr);
    chksumlen += sizeof(iphdr.ip6_dst.s6_addr);

    // Copy UDP length into buf (32 bits)
    memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
    ptr += sizeof(udphdr.len);
    chksumlen += sizeof(udphdr.len);

    // Copy zero field to buf (24 bits)
    memset(ptr, 0, 3);
    ptr += 3;
    chksumlen += 3;

    // Copy next header field to buf (8 bits)
    memcpy(ptr, &iphdr.ip6_nxt, sizeof(iphdr.ip6_nxt));
    ptr += sizeof(iphdr.ip6_nxt);
    chksumlen += sizeof(iphdr.ip6_nxt);

    // Copy UDP source port to buf (16 bits)
    memcpy(ptr, &udphdr.source, sizeof(udphdr.source));
    ptr += sizeof(udphdr.source);
    chksumlen += sizeof(udphdr.source);

    // Copy UDP destination port to buf (16 bits)
    memcpy(ptr, &udphdr.dest, sizeof(udphdr.dest));
    ptr += sizeof(udphdr.dest);
    chksumlen += sizeof(udphdr.dest);

    // Copy UDP length again to buf (16 bits)
    memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
    ptr += sizeof(udphdr.len);
    chksumlen += sizeof(udphdr.len);

    // Copy UDP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    memset(ptr, 0, 2);
    ptr += 2;
    chksumlen += 2;

    // Copy payload to buf
    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i = 0; i < payloadlen % 2; i++, ptr++)
    {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum((uint16_t *)buf, chksumlen);
}

/**
 * @brief Function to send IPV6 echo packets
 * 
 * @param interface inetrface name to which echo packet to be sent
 * @param MACaddress MAC address of destination hop
 * @return int return 0 on success / IHC_FAILURE on failure
 */

static int ihc_sendV6EchoPackets(char *interface, char *MACaddress)
{
    int status = 0;
    int datalen = 0;
    int frame_length = 0;
    int bytes = 0;
    struct ip6_hdr iphdr;
    struct udphdr udphdr;
    struct sockaddr_ll device;
    ifreq_t ifr;
    int sockV6 = IHC_FAILURE;
    char src_ip[INET6_ADDRSTRLEN] = {0};
    uint8_t data[IHC_MAX_STRING_LENGTH] = {0};
    uint8_t src_mac[IHC_MAX_STRING_LENGTH] = {0};
    uint8_t dst_mac[IHC_MAX_STRING_LENGTH] = {0};
    uint8_t ether_frame[IHC_MAX_STRING_LENGTH] = {0};
    char *mac = NULL;
    int macIdx = 0;
    char *tmp_ptr = NULL;
    char globalAddress[IHC_MAX_STRING_LENGTH] = {0};
    int ret = IHC_SUCCESS;
    int packet_priority = IHC_PRIORITY_MARKING;
    char *savePtr;

    if (interface == NULL || MACaddress == NULL)
    {
        IhcError("[%s:%d] Invalid args...", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    // Submit request for a socket descriptor to look up interface.
    if ((sockV6 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        IhcError("[%s:%d] socket() failed to get socket descriptor for using ioctl() : %s", __FUNCTION__, __LINE__, strerror(errno));
        return IHC_FAILURE;
    }

    // Use ioctl() to look up interface name and get its MAC address.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sockV6, SIOCGIFHWADDR, &ifr) < 0)
    {
        IhcError("ioctl() failed to get source MAC address : %s", strerror(errno));
        close(sockV6);
        return IHC_FAILURE;
    }
    close(sockV6);

    // Copy source MAC address.
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, IHC_MACADDR_LEN);

    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    memset(&device, 0, sizeof(device));
    if ((device.sll_ifindex = if_nametoindex(interface)) == 0)
    {
        IhcError("if_nametoindex() failed to obtain interface index : %s", strerror(errno));
        return IHC_FAILURE;
    }

    /* populate destination mac address */
    macIdx = 0;

    sscanf(MACaddress, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
            &dst_mac[macIdx++], &dst_mac[macIdx++], 
            &dst_mac[macIdx++], &dst_mac[macIdx++], 
            &dst_mac[macIdx++], &dst_mac[macIdx]);

    IhcInfo ("[%s :%d] BNG MAC %s",__FUNCTION__, __LINE__, MACaddress);
    if ((ret = ihc_get_ipv6_global_address(globalAddress, sizeof(globalAddress))) != IHC_SUCCESS)
    {
        IhcError("ihc_get_ipv6_global_address failed : %d ", ret);
        return IHC_FAILURE;
    }
    IhcInfo ("[%s :%d] V6 IP %s",__FUNCTION__, __LINE__, globalAddress);
    strncpy(src_ip, globalAddress, sizeof(src_ip) - 1);

    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, src_mac, IHC_MACADDR_LEN);
    device.sll_halen = IHC_MACADDR_LEN;

    // UDP data
    datalen = strlen("ECHO");
    memcpy(data, "ECHO", datalen);

    // IPv6 header

    // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    iphdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);

    // Payload length (16 bits): UDP header + UDP data
    iphdr.ip6_plen = htons(IHC_UDP_HDRLEN + datalen);

    // Next header (8 bits): 17 for UDP
    iphdr.ip6_nxt = IPPROTO_UDP;

    // Hop limit (8 bits): default to maximum value
    iphdr.ip6_hops = 255;

    //Source and destination IP is same for IHC  echo implementation
    // Source IPv6 address (128 bits)
    if ((status = inet_pton(AF_INET6, src_ip, &(iphdr.ip6_src))) != 1)
    {
        IhcError("inet_pton() failed.\nError message: %s", strerror(status));
        return IHC_FAILURE;
    }

    // Destination IPv6 address (128 bits)
    if ((status = inet_pton(AF_INET6, src_ip, &(iphdr.ip6_dst))) != 1)
    {
        IhcError("inet_pton() failed.Error message: %s", strerror(status));
        return IHC_FAILURE;
    }

    // UDP header
    // Source port number (16 bits): pick a number
    udphdr.source = htons(IHC_SOURCE_PORT);

    // Destination port number (16 bits): pick a number
    udphdr.dest = htons(IHC_DESTINATION_PORT);

    // Length of UDP datagram (16 bits): UDP header + UDP data
    udphdr.len = htons(IHC_UDP_HDRLEN + datalen);

    // UDP checksum (16 bits)
    if ((udphdr.check = udp6_checksum(iphdr, udphdr, data, datalen)) == 0)
    {
        IhcError("[%s %d] unable to generate checksum", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    // Fill out ethernet frame header.

    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + UDP header + UDP data)
    frame_length = IHC_MACADDR_LEN + IHC_MACADDR_LEN + IHC_ETHTYPE_LEN + IHC_IP6_HDRLEN + IHC_UDP_HDRLEN + datalen;

    // Destination and Source MAC addresses
    memcpy(ether_frame, dst_mac, IHC_MACADDR_LEN);
    memcpy(ether_frame + IHC_MACADDR_LEN, src_mac, IHC_MACADDR_LEN);

    // Next is ethernet type code (ETH_P_IPV6 for IPv6).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_IPV6 / 256;
    ether_frame[13] = ETH_P_IPV6 % 256;

    // Next is ethernet frame data (IPv6 header + UDP header + UDP data).

    // IPv6 header
    memcpy(ether_frame + IHC_ETH_HDRLEN, &iphdr, IHC_IP6_HDRLEN);

    // UDP header
    memcpy(ether_frame + IHC_ETH_HDRLEN + IHC_IP6_HDRLEN, &udphdr, IHC_UDP_HDRLEN);

    // UDP data
    memcpy(ether_frame + IHC_ETH_HDRLEN + IHC_IP6_HDRLEN + IHC_UDP_HDRLEN, data, datalen);

    // Submit request for a raw socket descriptor.
    if ((sockV6 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        IhcError("socket() failed : %s", strerror(errno));
        return IHC_FAILURE;
    }

    /* setting socket option to use MARK value(Priority 7 - high priority queue) */
    if (setsockopt(sockV6, SOL_SOCKET, SO_MARK, &packet_priority, sizeof(packet_priority)) < 0)
    {
        IhcError("socket marking failed : %s", strerror(errno));
        close(sockV6);
        return IHC_FAILURE;
    }
    // Send ethernet frame to socket.
    if ((bytes = sendto(sockV6, ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0)
    {
        IhcError("sendto() failed : %s", strerror(errno));
        close(sockV6);
        return IHC_FAILURE;
    }
    else
    {
        IhcInfo("Echo packets V6 TX [%u -> %u]", g_echo_V6_failure_count, g_echo_V6_failure_count + 1);
    }

    // Close V6 socket descriptor.
    close(sockV6);

    return IHC_SUCCESS;
}

/**
 * @brief Function to send IPV4 IHC echo packets
 * 
 * @param interface Interface to send the packets
 * @param MACaddress MAC address of the interface
 * @return int 0 on success / IHC_FAILURE on failure
 */
static int ihc_sendV4EchoPackets(char *interface, char *MACaddress)
{
    ifreq_t if_idx = {0};
    ifreq_t if_mac = {0};
    ifreq_t if_ip = {0};
    int tx_len = 0;
    char sendbuf[IHC_MAX_UDP_PACKET_LENGTH];
    struct ether_header *eh = (struct ether_header *)sendbuf;
    struct iphdr *iph;
    struct udphdr *udph;
    struct sockaddr_ll socket_address;
    int macIdx = 0;
    char *mac = NULL;
    char *tmp_ptr = NULL;
    int sockV4 = IHC_FAILURE;
    int packet_priority = IHC_PRIORITY_MARKING;
    char *savePtr = NULL;

    if (interface == NULL || MACaddress ==  NULL)
    {
        IhcError("[%s:%d] invalid args...", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    if ((sockV4 = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == IHC_FAILURE)
    {
        IhcError("socket creation failed");
        return IHC_FAILURE;
    }

    /* Get the interface index */
    memset(&if_idx, 0, sizeof(ifreq_t));
    strncpy(if_idx.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockV4, SIOCGIFINDEX, &if_idx) < 0)
    {
        IhcError("SIOCGIFINDEX failed: %s", strerror(errno));
        close(sockV4);
        return IHC_FAILURE;
    }

    /* Get the MAC address */
    memset(&if_mac, 0, sizeof(ifreq_t));
    strncpy(if_mac.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockV4, SIOCGIFHWADDR, &if_mac) < 0)
    {
        IhcError("SIOCGIFHWADDR failed: %s", strerror(errno));
        close(sockV4);
        return IHC_FAILURE;
    }

    /* Get the IP address of interface */
    memset(&if_ip, 0, sizeof(ifreq_t));
    strncpy(if_ip.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockV4, SIOCGIFADDR, &if_ip) < 0)
    {
        IhcError("SIOCGIFADDR failed: %s", strerror(errno));
        close(sockV4);
        return IHC_FAILURE;
    }

    memset(sendbuf, 0, sizeof(sendbuf));

    /* Ethernet header */
    for (macIdx =0; macIdx < IHC_MACADDR_LEN; macIdx++)
    {
        eh->ether_shost[macIdx] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[macIdx];
    }

    /* populate destination mac address */
    macIdx = 0;

    sscanf(MACaddress, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
            &eh->ether_dhost[macIdx++], &eh->ether_dhost[macIdx++], 
            &eh->ether_dhost[macIdx++], &eh->ether_dhost[macIdx++], 
            &eh->ether_dhost[macIdx++], &eh->ether_dhost[macIdx]);

    eh->ether_type = htons(ETH_P_IP);
    tx_len += sizeof(struct ether_header);

    iph = (struct iphdr *)(sendbuf + sizeof(struct ether_header));
    /* IP Header */
    iph->ihl = IHC_IP_HDRLEN;
    iph->version = IHC_IP_HDR_VERSION;
    iph->tos = IHC_IP_HDR_TOS; // Low delay
    iph->id = htons(IHC_IP_HDR_ID);
    iph->ttl = IHC_IP_HDR_TTL;              // hops - Max value
    iph->protocol = IPPROTO_UDP; // UDP

    /* Source IP address, can be spoofed */
    iph->saddr = inet_addr(inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr));
    iph->daddr = inet_addr(inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr));

    tx_len += sizeof(struct iphdr);

    udph = (struct udphdr *)(sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header));

    /* UDP Header */
    udph->source = htons(IHC_SOURCE_PORT);
    udph->dest = htons(IHC_DESTINATION_PORT);
    udph->check = 0; // skip
    tx_len += sizeof(struct udphdr);

    /* Packet data , sample data*/
    sendbuf[tx_len++] = 'E';
    sendbuf[tx_len++] = 'C';
    sendbuf[tx_len++] = 'H';
    sendbuf[tx_len++] = 'O';

    /* Length of UDP payload and header */
    udph->len = htons(tx_len - sizeof(struct ether_header) - sizeof(struct iphdr));

    /* Length of IP payload and header */
    iph->tot_len = htons(tx_len - sizeof(struct ether_header));

    /* Calculate IP checksum on completed header */
    if ((iph->check = csum((uint16_t *)(sendbuf + sizeof(struct ether_header)), sizeof(struct iphdr) / 2)) == 0)
    {
        IhcError("[%s:%d] Checksum calculation failed", __FUNCTION__, __LINE__);
        close(sockV4);
        return IHC_FAILURE;
    }

    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;

    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;

    while (macIdx <= 5)
    {
        socket_address.sll_addr[macIdx] = eh->ether_dhost[macIdx];
        macIdx++;
    }

    /* setting socket option to use MARK value(Priority 7 - high priority queue) */
    if (setsockopt(sockV4, SOL_SOCKET, SO_MARK, &packet_priority, sizeof(packet_priority)) < 0)
    {
        IhcError("socket marking failed : %s", strerror(errno));
        close(sockV4);
        return IHC_FAILURE;
    }

    /* Sending V4 IHC packets */
    if (sendto(sockV4, sendbuf, tx_len, MSG_DONTWAIT, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0)
    {
        IhcError("UDP sendto failed V4: %s", strerror(errno));
        close(sockV4);
        return IHC_FAILURE;
    }
    IhcInfo("Echo packets V4 TX [%u -> %u]", g_echo_V4_failure_count, g_echo_V4_failure_count + 1);

    close(sockV4); // close the socket
    return IHC_SUCCESS;

}


/**
 * @brief Create V6 echo packets listening socket
 * 
 * @return int success- actual socket/ failure IHC_FAILURE
 */
static int ihc_create_echo_reply_socket_v6()
{
    int     echo_reply_socket_v6 = IHC_FAILURE;
    int     optval;
    struct  sockaddr_in6 server_addr;
    struct  timeval timeout;

      /* create reply socket always */
    if ((echo_reply_socket_v6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
    {
        IhcError("echo reply socket V6 creation failed : %s", strerror(errno));
        return IHC_FAILURE;
    }

    optval = 1;
    if( setsockopt(echo_reply_socket_v6, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int)) )
    {
        IhcError("echo reply socket V6 SO_REUSEADDR flag set failed : %s", strerror(errno));
        close(echo_reply_socket_v6);
        return IHC_FAILURE;
    }

    optval = 1;
    if( setsockopt(echo_reply_socket_v6, IPPROTO_IPV6, IPV6_V6ONLY, (const void *)&optval , sizeof(int)) )
    {
        IhcError("echo reply socket V6 IPV6_V6ONLY flag set failed : %s", strerror(errno));
        close(echo_reply_socket_v6);
        return IHC_FAILURE;
    }

    timeout.tv_sec = IHC_ECHO_REPLY_TIME_OUT;
    timeout.tv_usec = 0;

    if (setsockopt(echo_reply_socket_v6, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        IhcError("setsockopt V6 failed for timeout : %s", strerror(errno));
        close(echo_reply_socket_v6);
        return IHC_FAILURE;
    }

    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(IHC_DESTINATION_PORT);

    if (bind(echo_reply_socket_v6, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) 
    {
        IhcError("V6 socket bind failed : %s", strerror(errno));
        close(echo_reply_socket_v6);
        return IHC_FAILURE;
    }

    IhcInfo("[%s:%d] Created ECHO Reply V6 socket : %d",__FUNCTION__, __LINE__, echo_reply_socket_v6);
    return echo_reply_socket_v6;
}

/**
 * @brief Create V4 echo packets listening socket
 * 
 * @return int success- actual socket/ failure IHC_FAILURE
 */
static int ihc_create_echo_reply_socket_v4()
{
    int     echo_reply_socket_v4 = IHC_FAILURE;
    int     optval;
    struct  sockaddr_in serveraddr; 
    struct  timeval timeout;

      /* create reply socket always */
    if ((echo_reply_socket_v4 = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        IhcError("echo reply socket creation V4 failed : %s", strerror(errno));
        return IHC_FAILURE;
    }

    optval = 1;
    if( setsockopt(echo_reply_socket_v4, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int)) )
    {
        IhcError("echo reply socket V4 SO_REUSEADDR flag set failed : %s", strerror(errno));
        close(echo_reply_socket_v4);
        return IHC_FAILURE;
    }

    timeout.tv_sec = IHC_ECHO_REPLY_TIME_OUT;
    timeout.tv_usec = 0;

    if (setsockopt(echo_reply_socket_v4, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        IhcError("setsockopt failed for timeout : %s", strerror(errno));
        close(echo_reply_socket_v4);
        return IHC_FAILURE;
    }

    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((uint16_t)IHC_DESTINATION_PORT);

    if (bind(echo_reply_socket_v4, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) 
    {
        IhcError("v4 socket bind failed : %s", strerror(errno));
        close(echo_reply_socket_v4);
        return IHC_FAILURE;
    }

    IhcInfo("[%s:%d] Created ECHO Reply V4 socket : %d",__FUNCTION__, __LINE__, echo_reply_socket_v4);
    return echo_reply_socket_v4;
}


static int ihc_resolve_domain_name(char * domainName)
{
    if (domainName == NULL || strlen(domainName) <= 0)
    {
        IhcInfo("%s %d: No domainName provided. So cannot check resolution\n", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    char ip[64]={0};
    struct addrinfo hints, *result, *rp;
    memset(&hints, '\0', sizeof(hints));

    int error = getaddrinfo(domainName, NULL, &hints, &result);

    if (error != 0)
    {
        IhcError("%s %d: unable to resolve Domain Name:%s\n", __FUNCTION__, __LINE__, domainName);
        return IHC_FAILURE;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) 
    {
        inet_ntop(AF_INET, &rp->ai_addr->sa_data[1], (char *)&ip, sizeof(ip));
        IhcInfo("IP address: %s\n\n", ip);
        inet_ntop(AF_INET, &rp->ai_addr->sa_data[2], (char *)&ip, sizeof(ip));
        IhcInfo("IP address2: %s\n\n", ip);
    }

    return IHC_SUCCESS;

}

static int ihc_domain_name_update(char *msg_domainName, char *domainName, int size)
{
    if (domainName == NULL || msg_domainName == NULL ||  size <= 0)
    {
        IhcInfo("%s %d: invalid args\n", __FUNCTION__, __LINE__);
        return IHC_FAILURE;
    }

    if((msg_domainName[0] != '\0') && (strcmp(msg_domainName, domainName) != 0))
    {
        snprintf(domainName, size, "%s", msg_domainName);
        IhcInfo("%s %d: Domain Name update success = [%s]\n", __FUNCTION__, __LINE__, domainName);
    }

    return IHC_SUCCESS;
}

/**
 * @brief handle messages and IHC echo packets
 * 
 * @return int return IHC_SUCCESS / error
 */

int ihc_echo_handler(void)
{
    fd_set r_fds;
    struct timeval timeout;
    int fdCount = 0;
    int ret = IHC_SUCCESS;
    int bytes = 0;
    struct sockaddr srcAddr;
    socklen_t sendsize = 0;
    uint8_t recvBuf[IHC_MAX_UDP_PACKET_LENGTH];
    uint32_t echoElapsedTimeV4 = 0;
    uint32_t echoElapsedTimeV6 = 0;
    struct timespec echoTime;
    char defaultGatewayV4[IHC_MAX_STRING_LENGTH] = {0};
    char defaultGatewayV6[IHC_MAX_STRING_LENGTH] = {0};
    char BNGMACAddressV4[IHC_MAX_STRING_LENGTH] = {0};
    char BNGMACAddressV6[IHC_MAX_STRING_LENGTH] = {0};
    char sysevent_name[] = "ipoe_sysevent";
    int echo_reply_socket_v4 = IHC_FAILURE;
    int echo_reply_socket_v6 = IHC_FAILURE;
    int ipv4_echo_time_interval = IHC_DEFAULT_REGULAR_INTERVAL;
    int ipv6_echo_time_interval = IHC_DEFAULT_REGULAR_INTERVAL;
    uint16_t msgSize = 0;
    ipc_ihc_data_t msgBody;

    msgSize = sizeof(ipc_ihc_data_t);

    char domainName[128] = {0};

    // init wan connection data
    memset(&wanConnectionData, 0, msgSize);

    sysevent_fd =  sysevent_open(SYS_IP_ADDR, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, sysevent_name, &sysevent_token);

    for (;;)
    {
        bytes = nn_recv(ipcListenFd, (ipc_ihc_data_t *)&msgBody, msgSize, NN_DONTWAIT);
        /* Check if the message is for the interface IHC is running */
        if (bytes == msgSize && (!IS_EMPTY_STRING(msgBody.ifName)) && (strcmp(msgBody.ifName, g_ifName) == 0))
        {
            //Handle message from Wan Manager
            switch (msgBody.msgType)
            {
                case IPOE_MSG_WAN_CONNECTION_UP:
                    IhcInfo("===== IPOE_MSG_WAN_CONNECTION_UP event received Intf = %s ======", msgBody.ifName);

                    /* Store wan connection data */
                    strncpy(wanConnectionData.ifName, msgBody.ifName, sizeof(wanConnectionData.ifName));
                    strncpy(wanConnectionData.ipv4Address, msgBody.ipv4Address, sizeof(wanConnectionData.ipv4Address));
                    ihc_domain_name_update(msgBody.domainName, domainName, sizeof(domainName));

                    /* Start V4 IHC echo packet transmission */

                    /* DEV-2321 HUB4 - Not sending IPV4 request after 3 renewal - IPoE health check enabled build
                     * Adapt to Broadcom application architecture specification (notes in Jira).
                     */
                    if( echo_reply_socket_v4 == IHC_FAILURE && (echo_reply_socket_v4 = ihc_create_echo_reply_socket_v4()) == IHC_FAILURE )
                    {
                        IhcError("v4 echo socket creation failed : %s", strerror(errno));
                        return IHC_FAILURE;
                    }

                    if( ihc_start_echo_packets(IHC_ECHO_TYPE_V4) >= 0)
                    {
                        g_v4_connection = TRUE;
                        /*...After V4 UP, waite for 30s to send echo */
                        ipv4_echo_time_interval = IHC_DEFAULT_REGULAR_INTERVAL; //Regular Interval 30s
                    }
                    break;

                case IPOE_MSG_WAN_CONNECTION_DOWN:
                    IhcInfo("===== IPOE_MSG_WAN_CONNECTION_DOWN event received ======");
                    /* Reset wan connection data */
                    memset(wanConnectionData.ipv4Address, 0, sizeof(wanConnectionData.ipv4Address));

                    /* Stop V4 IHC echo packet transmission */
                    ihc_stop_echo_packets(IHC_ECHO_TYPE_V4);
                    ipv4_echo_time_interval = IHC_DEFAULT_RETRY_INTERVAL;
                    break;

                case IPOE_MSG_WAN_CONNECTION_IPV6_UP:
                    IhcInfo("===== IPOE_MSG_WAN_CONNECTION_IPV6_UP event received Intf = %s ======", msgBody.ifName);
                    /* Store wan connection data */
                    strncpy(wanConnectionData.ifName, msgBody.ifName, sizeof(wanConnectionData.ifName));
                    strncpy(wanConnectionData.ipv6Address, msgBody.ipv6Address, sizeof(wanConnectionData.ipv6Address));
                    ihc_domain_name_update(msgBody.domainName, domainName, sizeof(domainName));

                    /* Start V6 IHC echo packet transmission */

                    /* DEV-2321 HUB4 - Not sending IPV4 request after 3 renewal - IPoE health check enabled build
                     * Adapt to Broadcom application architecture specification (notes in Jira).
                     */
                    if( echo_reply_socket_v6 == IHC_FAILURE && (echo_reply_socket_v6 = ihc_create_echo_reply_socket_v6()) == IHC_FAILURE )
                    {
                        IhcError("v6 echo socket creation failed : %s", strerror(errno));
                        return IHC_FAILURE;
                    }

                    if( ihc_start_echo_packets(IHC_ECHO_TYPE_V6) >= 0)
                    {
                        g_v6_connection = TRUE;
                        /*...After V6 UP, waite for 30s to send echo */
                        ipv6_echo_time_interval = IHC_DEFAULT_REGULAR_INTERVAL; //Regular Interval 30s
                    }
                    break;

                case IPOE_MSG_WAN_CONNECTION_IPV6_DOWN:
                    IhcInfo("===== IPOE_MSG_WAN_CONNECTION_IPV6_DOWN event received ======");
                    /* Reset wan connection data */
                    memset(wanConnectionData.ipv6Address, 0, sizeof(wanConnectionData.ipv6Address));

                    /* Stop V6 IHC echo packet transmission */
                    ihc_stop_echo_packets(IHC_ECHO_TYPE_V6);
                    ipv6_echo_time_interval = IHC_DEFAULT_RETRY_INTERVAL;
                    break;

                default:
                    IhcError("IHC: Unknown Message 0x%X", msgBody.msgType);
                    break;
            }
        }

        if (echo_reply_socket_v4 != IHC_FAILURE || echo_reply_socket_v6 != IHC_FAILURE)
        {
            FD_ZERO(&r_fds);
            if (echo_reply_socket_v4 != IHC_FAILURE)
            {
                FD_SET(echo_reply_socket_v4, &r_fds);

                if( echo_reply_socket_v4 > fdCount )
                {
                    fdCount = echo_reply_socket_v4;
                }
            }

            if (echo_reply_socket_v6 != IHC_FAILURE)
            {
                FD_SET(echo_reply_socket_v6, &r_fds);

                if( echo_reply_socket_v6 > fdCount )
                {
                    fdCount = echo_reply_socket_v6;
                }
            }

            timeout.tv_sec = IHC_LOOP_TIMOUT; // 1 sec wakeup
            timeout.tv_usec = 0;

            while ( (ret = select(fdCount + 1, &r_fds, NULL, NULL, &timeout)) == IHC_FAILURE && errno == EINTR)
                continue;
            if (ret < 0)
            {
                IhcError("select failed with errno = %s", strerror(errno));
                perror("IHC ERROR: during select ");
                return IHC_FAILURE;
            }

            if (FD_ISSET(echo_reply_socket_v4, &r_fds))
            {
                if (recvfrom(echo_reply_socket_v4, recvBuf, sizeof(recvBuf), 0, &srcAddr, &sendsize) < 0)
                {
                    IhcError("echo reply recvfrom failed: %s", strerror(errno));
                }
                else
                {
                    /*
                     * - Startup sequence :- Continous 3 success echo (Continous 3 Failure echo leads to IDLE state)
                     * - Normal sequence  :- Starts after successful 'Startup sequence'
                     * -------- echo_time_interval---------------
                     * a) Till 'Startup sequence' success    : 10s
                     * b) Any echo failure                   : 10s
                     * c) Success echo in 'Normal sequence   : 30s
                     */
                    if(v4_startup_sequence_completed == FALSE)
                    {
                        ipv4_echo_time_interval = IHC_DEFAULT_RETRY_INTERVAL; //Retry Interval 10s

                        if( g_echo_V4_failure_count == 1 )
                        {
                            g_echo_V4_success_count++;
                            if( g_echo_V4_success_count >= IHC_DEFAULT_LIMIT )
                            {
                                IhcNotice("IHC_V4_STARTUP_COMPLETED :: IHC: IPOE health check(IPv4) startup sequence completed");
                                v4_startup_sequence_completed = TRUE;
                                ipv4_echo_time_interval = IHC_DEFAULT_REGULAR_INTERVAL; //Regular Interval 30s
                                /* Send the message to WAN Manager that the IPv4 connection is up */
                                if (ihc_broadcastEvent(IPOE_MSG_IHC_ECHO_IPV4_UP) != IHC_SUCCESS)
                                {
                                    IhcError("Sending IPOE_MSG_IHC_ECHO_IPV4_UP failed");
                                }
                                // ping to v4 gw is success.
                                // Set sysevent so that other modules(eg: selfheal) can detect the gw status for logging purpose
                                if(sysevent_fd != -1)
                                {
                                    sysevent_set(sysevent_fd, sysevent_token, IPOE_HEALTH_CHECK_V4_STATUS, IPOE_STATUS_SUCCESS, 0);
                                }
                            }
                        }
                        else
                        {
                            g_echo_V4_success_count = 1;
                        }

                        if( ( FALSE == Is_v4_bfd_1stpkt_success_occurs ) && ( 0 < g_echo_V4_success_count ) )
                        {
                            IhcNotice("IHC_V4_1ST_PKT_SUCCESS :: IHC: IPOE health check(IPv4) first packet success");
                            Is_v4_bfd_1stpkt_success_occurs = TRUE;
                        }
                    }
                    else // Normal Operation
                    {
                        ipv4_echo_time_interval = IHC_DEFAULT_REGULAR_INTERVAL; //Regular Interval 30s
                    }
                    IhcInfo("Echo packets V4 RX [%u -> 0]", g_echo_V4_failure_count);
                    g_echo_V4_failure_count = 0;
                }
            }

            if (FD_ISSET(echo_reply_socket_v6, &r_fds))
            {
                if (recvfrom(echo_reply_socket_v6, recvBuf, sizeof(recvBuf), 0, &srcAddr, &sendsize) < 0)
                {
                    IhcError("echo reply recvfrom failed: %s", strerror(errno));
                }
                else
                {
                    /*
                     * - Startup sequence :- Continous 3 success echo (Continous 3 Failure echo leads to IDLE state)
                     * - Normal sequence  :- Starts after successful 'Startup sequence'
                     * -------- echo_time_interval---------------
                     * a) Till 'Startup sequence' success    : 10s
                     * b) Any echo failure                   : 10s
                     * c) Success echo in 'Normal sequence   : 30s
                     */
                    if(v6_startup_sequence_completed == FALSE)
                    {
                        ipv6_echo_time_interval = IHC_DEFAULT_RETRY_INTERVAL; //Retry Interval 10s

                        if( g_echo_V6_failure_count == 1 )
                        {
                            g_echo_V6_success_count++;
                            if( g_echo_V6_success_count >= IHC_DEFAULT_LIMIT )
                            {
                                IhcNotice("IHC_V6_STARTUP_COMPLETED :: IHC: IPOE health check(IPv6) startup sequence completed");
                                v6_startup_sequence_completed = TRUE;
                                ipv6_echo_time_interval = IHC_DEFAULT_REGULAR_INTERVAL; //Regular Interval 30s
                                /* Send a message to WAN Manager that the IPV6 connection is up */
                                if (ihc_broadcastEvent(IPOE_MSG_IHC_ECHO_IPV6_UP) != IHC_SUCCESS)
                                {
                                    IhcError("Sending IPOE_MSG_IHC_ECHO_IPV6_UP failed");
                                }
                                // ping to v6 gw is success.
                                // Set sysevent so that other modules(eg: selfheal) can detect the gw status for logging purpose
                                if(sysevent_fd != -1)
                                {
                                    sysevent_set(sysevent_fd, sysevent_token, IPOE_HEALTH_CHECK_V6_STATUS, IPOE_STATUS_SUCCESS, 0);
                                }
                            }
                        }
                        else
                        {
                            g_echo_V6_success_count = 1;
                        }

                        if( ( FALSE == Is_v6_bfd_1stpkt_success_occurs ) && ( 0 < g_echo_V6_success_count ) )
                        {
                            IhcNotice("IHC_V6_1ST_PKT_SUCCESS :: IHC: IPOE health check(IPv6) first packet success");
                            Is_v6_bfd_1stpkt_success_occurs = TRUE;
                        }
                    }
                    else // Normal Operation
                    {
                        ipv6_echo_time_interval = IHC_DEFAULT_REGULAR_INTERVAL; //Regular Interval 30s
                    }
                    IhcInfo("Echo packets V6 RX [%u -> 0]", g_echo_V6_failure_count);
                    g_echo_V6_failure_count = 0;
                }
            }

        }

        if (g_send_V4_echo || g_send_V6_echo) /* either V4 echo send flag or V6 echo send flag is true */
        {
            if (!clock_gettime(CLOCK_MONOTONIC, &echoTime))
            {
                uint32_t delta = (echoTime.tv_sec + (echoTime.tv_nsec / NANOSEC2SEC)) - echoElapsedTimeV4;
                /* Take the difference , If the delta time is greater on equal to echo timer interval send the echo packets */
                if (delta >= ipv4_echo_time_interval)
                {
                    if (g_echo_V4_failure_count >= IHC_DEFAULT_LIMIT) /* broadcast V4 IHC failres */
                    {
                        if (g_send_V4_echo)
                        {
                            IhcInfo("[%s:%d] v4 echo reply failure reached threshold", __FUNCTION__, __LINE__);
                            /*...Send RENEW/RELAESE in 'Normal Sequence'... */
                            if( v4_startup_sequence_completed )
                            {
                                /*...Send RELEASE if wan_v4_release = TRUE (This will be set from Request packets of SKYDHCPC)...*/
                                if( wan_v4_release ) //RELEASE
                                {
                                    IhcInfo("[%s:%d] Sending IPOE_MSG_IHC_ECHO_FAIL_IPV4 failure message to WanManager", __FUNCTION__, __LINE__);
                                    if (ihc_broadcastEvent(IPOE_MSG_IHC_ECHO_FAIL_IPV4) != IHC_SUCCESS)
                                    {
                                        IhcError("Sending IPOE_MSG_IHC_ECHO_FAIL_IPV4 failed");
                                    }
                                }
                                else  /*...Send RENEW if wan_v4_release = FALSE (This will be set from Request packets of SKYDHCPC)...*/
                                {
                                    IhcInfo("[%s:%d] Sending IPOE_MSG_IHC_ECHO_RENEW_IPV4", __FUNCTION__, __LINE__);

                                    if (ihc_broadcastEvent(IPOE_MSG_IHC_ECHO_RENEW_IPV4) != IHC_SUCCESS)
                                    {
                                        IhcError("Sending IPOE_MSG_IHC_ECHO_FAIL_IPV4 failed");
                                    }
                                }
                                IhcError("IHC_V4_FAIL :: IHC: IPOE health check for IPv4 has failed");
                            }
                            else  /*...IPOE v4 check goes to IDLE after 3 continuous Failre echo in 'Startup Sequence'... */
                            {
                                if (ihc_resolve_domain_name(domainName) != IHC_SUCCESS)
                                {
                                    IhcError("%s %d:  Domain Nameresolution failed\n", __FUNCTION__, __LINE__);
                                    /*...Send RELEASE if wan_v4_release = TRUE (This will be set from Request packet)...*/
                                    if( wan_v4_release ) //RELEASE
                                    {
                                        IhcInfo("[%s:%d] Sending IPOE_MSG_IHC_ECHO_FAIL_IPV4 failure message to WanManager", __FUNCTION__, __LINE__);
                                        if (ihc_broadcastEvent(IPOE_MSG_IHC_ECHO_FAIL_IPV4) != IHC_SUCCESS)
                                        {
                                            IhcError("Sending IPOE_MSG_IHC_ECHO_FAIL_IPV4 failed");
                                        }
                                    }
                                    else  /*...Send RENEW if wan_v4_release = FALSE (This will be set from Request packet)...*/
                                    {
                                        IhcInfo("[%s:%d] Sending IPOE_MSG_IHC_ECHO_RENEW_IPV4", __FUNCTION__, __LINE__);

                                        if (ihc_broadcastEvent(IPOE_MSG_IHC_ECHO_RENEW_IPV4) != IHC_SUCCESS)
                                        {
                                            IhcError("Sending IPOE_MSG_IHC_ECHO_FAIL_IPV4 failed");
                                        }
                                    }
                                }
                                else
                                {
                                    IhcError("IHC_V4_IDLE :: IHC: IPOE health check(IPv4) IDLE");
                                }
                            }
                            ihc_stop_echo_packets(IHC_ECHO_TYPE_V4);
                            ipv4_echo_time_interval = IHC_DEFAULT_RETRY_INTERVAL;
                        }
                        // ping to v4 gw failed and reached limit.
                        // Set sysevent so that other modules(eg: selfheal) can detect the gw status for logging purpose
                        if(sysevent_fd != -1)
                        {
                            sysevent_set(sysevent_fd, sysevent_token, IPOE_HEALTH_CHECK_V4_STATUS, IPOE_STATUS_FAILED, 0);
                        }

                    }

                    if (g_send_V4_echo)
                    {
                        char wanInterface[IHC_MAX_STRING_LENGTH] = {0};
                        if ((ret = ihc_get_V4_defgateway_wan_interface(wanInterface, sizeof(wanInterface), defaultGatewayV4, sizeof(defaultGatewayV4))) == IHC_SUCCESS)
                        {
                            IhcInfo("[%s:%d] Sending V4 echo packets interface [%s] defaultGateway [%s]", __FUNCTION__, __LINE__, wanInterface, defaultGatewayV4);

                            char BNGMACAddress[IHC_MAX_STRING_LENGTH] = {0};
                            // if current arp entry has a valid entry , update the global mac array BNGMACAddressV4
                            if (ihc_get_V4_bng_MAC_address(defaultGatewayV4, BNGMACAddress , sizeof(BNGMACAddress)) == IHC_SUCCESS)
                            {
                                // update the global mac cache array if this is a new mac from arp cache
                                if( strncasecmp(BNGMACAddressV4,BNGMACAddress, strlen(BNGMACAddress)) != 0) 
                                {
                                    strncpy(BNGMACAddressV4, BNGMACAddress, IHC_MAX_STRING_LENGTH); //Cache BNG MAC address
                                }
                            }
                            /* There are different reasons for a lost mac in arp cache. ipoe session should always be active
                            irrespective of arp cache entry. So send the packet using the current GW mac kept in mac array
                            */
                            if( validateMacAddr(BNGMACAddressV4) == IHC_SUCCESS ) // Send V4 echo packets
                            {
                                char tmpBNGMACAddress[IHC_MAX_STRING_LENGTH] = {0};
                                strncpy(tmpBNGMACAddress, BNGMACAddressV4, IHC_MAX_STRING_LENGTH);
                                if (!ihc_sendV4EchoPackets(wanInterface, tmpBNGMACAddress))
                                {
                                    ipv4_echo_time_interval = IHC_DEFAULT_RETRY_INTERVAL;

                                    if( ( FALSE == Is_v4_bfd_1stpkt_failure_occurs ) && ( 0 <  g_echo_V4_failure_count ) )
                                    {
                                        IhcError("IHC_V4_1ST_PKT_FAILURE :: IHC: IPOE health check(IPv4) first packet failure");
                                        Is_v4_bfd_1stpkt_failure_occurs = TRUE;
                                    }

                                    g_echo_V4_failure_count++;
                                }
                                else
                                {
                                    IhcError("ihc_sendV4EchoPackets failed %s", strerror(errno));
                                    g_echo_V4_failure_count++;
                                }
                                echoElapsedTimeV4 = echoTime.tv_sec + echoTime.tv_nsec / NANOSEC2SEC;
                            }
                            else
                            {
                                IhcNotice("ihc_sendV4EchoPackets invalid BNGMAC[%s]", BNGMACAddressV4);
                            }
                        }
                        else
                        {
                            IhcInfo("ihc_get_V4_defgateway_wan_interface failed %d", ret); /* it can fail in PPP connection */
                        }
                    }
                }

                delta = (echoTime.tv_sec + (echoTime.tv_nsec / NANOSEC2SEC)) - echoElapsedTimeV6;

                if(delta >= ipv6_echo_time_interval)
                {
                    if (g_echo_V6_failure_count >= IHC_DEFAULT_LIMIT) /* broadcast V6 IHC failures */
                    {
                        if (g_send_V6_echo)
                        {
                            IhcInfo("[%s:%d] v6 echo reply failure reached threshold", __FUNCTION__, __LINE__);
                            /*...Send RENEW/RELAESE in 'Normal Sequence'... */
                            if( v6_startup_sequence_completed )
                            {
                                /*...Send RELEASE if wan_v6_release = TRUE (This will be set from Request packets of DHCPC6)...*/
                                if( wan_v6_release ) //RELEASE
                                {
                                    IhcInfo("Sending IPOE_MSG_IHC_ECHO_FAIL_IPV6 failure");
                                    if (ihc_broadcastEvent(IPOE_MSG_IHC_ECHO_FAIL_IPV6) != IHC_SUCCESS)
                                    {
                                        IhcError("Sending IPOE_MSG_IHC_ECHO_FAIL_IPV6 failed");
                                    }
                                }
                                else  /*...Send RENEW if wan_v6_release = FALSE (This will be set from Request packets of DHCPC6)...*/
                                {
                                    IhcInfo("Sending IPOE_MSG_IHC_ECHO_RENEW_IPV6");

                                    if (ihc_broadcastEvent(IPOE_MSG_IHC_ECHO_RENEW_IPV6) != IHC_SUCCESS)
                                    {
                                        IhcError("Sending IPOE_MSG_IHC_ECHO_FAIL_IPV6 failed");
                                    }
                                }
                                IhcError("IHC_V6_FAIL :: IHC: IPOE health check for IPv6 has failed");
                            }
                            else  /*...IPOE v6 check goes to IDLE after 3 continuous Failre echo in 'Startup Sequence'... */
                            {
                                if (ihc_resolve_domain_name(domainName) != IHC_SUCCESS)
                                {
                                    IhcError("%s %d: Domain Name resolution failed\n", __FUNCTION__, __LINE__);
                                    /*...Send RELEASE if wan_v6_release = TRUE (This will be set from Request packets)...*/
                                    if( wan_v6_release ) //RELEASE
                                    {
                                        IhcInfo("[%s:%d] Sending IPOE_MSG_IHC_ECHO_FAIL_IPV6 failure message to WanManager", __FUNCTION__, __LINE__);
                                        if (ihc_broadcastEvent(IPOE_MSG_IHC_ECHO_FAIL_IPV6) != IHC_SUCCESS)
                                        {
                                            IhcError("Sending IPOE_MSG_IHC_ECHO_FAIL_IPV6 failed");
                                        }
                                    }
                                    else  /*...Send RENEW if wan_v6_release = FALSE (This will be set from Request packets)...*/
                                    {
                                        IhcInfo("[%s:%d] Sending IPOE_MSG_IHC_ECHO_RENEW_IPV6", __FUNCTION__, __LINE__);

                                        if (ihc_broadcastEvent(IPOE_MSG_IHC_ECHO_RENEW_IPV6) != IHC_SUCCESS)
                                        {
                                            IhcError("Sending IPOE_MSG_IHC_ECHO_FAIL_IPV6 failed");
                                        }
                                    }
                                }
                                else
                                {
                                    IhcError("IHC_V6_IDLE :: IHC: IPOE health check(IPv6) IDLE");
                                }
                            }
                            ihc_stop_echo_packets(IHC_ECHO_TYPE_V6);
                            ipv6_echo_time_interval = IHC_DEFAULT_RETRY_INTERVAL;
                        }
                        // ping to v6 gw failed and reached limit. 
                        // Set sysevent so that other modules(eg: selfheal) can detect the gw status for logging purpose
                        if(sysevent_fd != -1)
                        {
                            sysevent_set(sysevent_fd, sysevent_token, IPOE_HEALTH_CHECK_V6_STATUS, IPOE_STATUS_FAILED, 0);
                        }
                    }

                    if (g_send_V6_echo)
                    {
                        char wanInterface[IHC_MAX_STRING_LENGTH] = {0};
                        if ((ret = ihc_get_V6_defgateway_wan_interface(wanInterface, sizeof(wanInterface), defaultGatewayV6, sizeof(defaultGatewayV6))) == IHC_SUCCESS)
                        {
                            IhcInfo("Sending V6 echo packets interface [%s] defaultGateway [%s]", wanInterface, defaultGatewayV6);
                            char BNGMACAddress[IHC_MAX_STRING_LENGTH] = {0};

                            //update global mac array if arp cacahe has a new valid mac entry for GW
                            if (ihc_get_V6_bng_MAC_address(defaultGatewayV6, BNGMACAddress, sizeof(BNGMACAddress)) == IHC_SUCCESS)
                            {
                                if( strncasecmp(BNGMACAddressV6, BNGMACAddress, strlen(BNGMACAddress)) ) 
                                {
                                    strncpy(BNGMACAddressV6, BNGMACAddress, IHC_MAX_STRING_LENGTH); 
                                }
                            }
                            /* There are different reasons for a lost mac in arp cache. ipoe session should always be active
                            irrespective of arp cache entry. So send the packet using the current GW mac kept in mac array
                            */
                            if( validateMacAddr(BNGMACAddressV6) == IHC_SUCCESS ) // Send V6 echo packets
                            {
                                char tmpBNGMACAddress[IHC_MAX_STRING_LENGTH] = {0};
                                strncpy(tmpBNGMACAddress, BNGMACAddressV6, IHC_MAX_STRING_LENGTH);
                                if (!ihc_sendV6EchoPackets(wanInterface, tmpBNGMACAddress))
                                {
                                    ipv6_echo_time_interval = IHC_DEFAULT_RETRY_INTERVAL;

                                    if( ( FALSE == Is_v6_bfd_1stpkt_failure_occurs ) && ( g_echo_V6_failure_count > 0 ) )
                                    {
                                        IhcError("IHC_V6_1ST_PKT_FAILURE :: IHC: IPOE health check(IPv6) first packet failure");
                                        Is_v6_bfd_1stpkt_failure_occurs = TRUE;
                                    }

                                    g_echo_V6_failure_count++;
                                }
                                else
                                {
                                    IhcError("ihc_sendV6EchoPackets failed %s", strerror(errno));
                                    g_echo_V6_failure_count++;
                                }

                                if (!clock_gettime(CLOCK_MONOTONIC, &echoTime))
                                {
                                    echoElapsedTimeV6 = echoTime.tv_sec + echoTime.tv_nsec / NANOSEC2SEC;
                                }
                            }
                            else
                            {
                                IhcNotice("ihc_sendV6EchoPackets invalid BNGMAC[%s]",BNGMACAddressV6);
                            }
                        }
                        else
                        {
                            IhcInfo("ihc_get_defgateway_wan_interface V6 failed %d", ret); /* it can fail in PPP connections */
                        }
                    }
                }
            }
        }
        else
        {
            /* Avoid busy waiting if wan is down during process start */
            sleep(1);
        }
    }
    if (0 <= sysevent_fd)
    {
        sysevent_close(sysevent_fd, sysevent_token);
    }
    return ret;  // We never actually reach this
}
