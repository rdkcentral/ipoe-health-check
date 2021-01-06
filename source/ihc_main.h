#ifndef __IHC_H__
#define __IHC_H__
/*
 * Copyright (C) 2020 Sky
 * --------------------------------------------------------------------------
 * THIS SOFTWARE CONTRIBUTION IS PROVIDED ON BEHALF OF SKY PLC.
 * BY THE CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED
 * ******************************************************************
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/


#include "ipc_msg.h"

/********************** Defines ***********************/

/*

2.2.4.13 - IPoE health probe messages shall be sent every 30 seconds
2.2.4.14 - If an echo message is lost, the product shall send echo messages every 10 seconds
2.2.4.15 - If four consecutive echo messages are lost, the IP session on the BNG is unreachable, and the product shall establish a 
new IP session by sending DHCP DISCOVER / SOLICIT messages. NOTE: when running in dual-stack mode, the v4 and v6 sessions are independent, 
as are the health check functions. That is, it is not necessary to restart both sessions if only one has lost BNG connectivity.

*/

#define IHC_DEFAULT_LIMIT            3
#define IHC_DEFAULT_REGULAR_INTERVAL 30
#define IHC_DEFAULT_RETRY_INTERVAL   10
#define IHC_IFNAME_LENGTH            32
#define IHC_FAILURE                  -1
#define IHC_SUCCESS                  0

extern  char g_ifName [IFNAME_LENGTH];

/********************** Enums *************************/

typedef enum
{
    IHC_ECHO_TYPE_V4 = 1,
    IHC_ECHO_TYPE_V6
}eIHCEchoType;

typedef uint8_t    UBOOL8;
typedef struct ifreq ifreq_t;

#define IhcError(fmt, arg...) \
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IHC", fmt "\n", ##arg);
#define IhcNotice(fmt, arg...) \
        RDK_LOG(RDK_LOG_NOTICE, "LOG.RDK.IHC", fmt "\n", ##arg);
#define IhcDebug(fmt, arg...) \
        RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IHC", fmt "\n", ##arg);

/********************** Function declarations **********/
int ihc_echo_handler(void);

#include "rdk_debug.h"
#endif //__IHC_H__
