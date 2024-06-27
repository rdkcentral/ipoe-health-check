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

/************************* Generic system includes *********************/
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>

#include "ihc_main.h"
/**************************** Global declarations *********************/
int   ipcListenFd;
char g_ifName [IFNAME_LENGTH];

#ifdef FEATURE_SUPPORT_RDKLOG
#define DEBUG_INI_NAME  "/etc/debug.ini"
#define RDK_LOG_COMP_NAME "LOG.RDK.IHC"

/* Initialize RDK Logger. */
static void LOGInit()
{
    rdk_logger_init(DEBUG_INI_NAME);
}
#endif //FEATURE_SUPPORT_RDKLOG

/**
 * @brief Entry point function for IHC
 * 
 * @param argc 
 * @param argv 
 * @return int 0 on success / -1 on failure
 */
int main(int argc, char *argv[])
{
    char *ifName = NULL;
    int   i = 0;
    int c;

#ifdef FEATURE_SUPPORT_RDKLOG
    /* Initialize RDK Logger. */
    LOGInit();
#endif //FEATURE_SUPPORT_RDKLOG

    while ((c = getopt (argc, argv, "i:")) != -1)
        switch (c)
        {
            case 'i':
                ifName = optarg;
                break;
            case '?':
                if (optopt == 'i')
                {
                    IhcError("Option -%c requires an argument.", optopt);
                }
                else if (isprint (optopt))
                {
                    IhcError("Unknown option `-%c'.", optopt);
                }
                else
                {
                    IhcError("Unknown option character.");
                }
                exit(IHC_FAILURE);
            default:
                IhcError("Unknown args.");
                exit(IHC_FAILURE);
        }

    if ((argc - optind) > 0 || strlen(ifName) > IFNAME_LENGTH)
    {
        IhcError("Invalid args\nexiting..\n");
        return IHC_FAILURE;
    }

    memset (g_ifName, IFNAME_LENGTH, 0);
    strncpy(g_ifName, ifName, IFNAME_LENGTH - 1);

    IhcInfo("Starting IPoE Health Check for Interface = %s", g_ifName);
    if ((ipcListenFd = nn_socket(AF_SP, NN_PULL)) < 0)
    {
        IhcError("Error[%s]:unable to create nn_socket()\n",nn_strerror(nn_errno ()));
        return IHC_FAILURE;
    }
    if ((i = nn_bind(ipcListenFd, IHC_IPC_ADDR)) < 0)
    {
        IhcError("Error[%s]: unable to bind to %s\n", nn_strerror(nn_errno ()), IHC_IPC_ADDR);
        nn_close(ipcListenFd);
        return IHC_FAILURE;
    }
    
    ihc_echo_handler(); /* infinite loop with 1 second delay */

    return IHC_SUCCESS;
}
