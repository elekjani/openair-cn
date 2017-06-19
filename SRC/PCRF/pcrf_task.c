/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under 
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.  
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#define PCRF
#define PCRF_TASK_C

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>

#include <libxml/xmlwriter.h>
#include <libxml/xpath.h>
#include "bstrlib.h"
#include "queue.h"

#include "hashtable.h"
#include "log.h"
#include "common_defs.h"
#include "common_types.h"
#include "intertask_interface.h"
#include "itti_free_defined_msg.h"
#include "spgw_config.h"
#include "sgw_handlers.h"
#include "sgw.h"

extern sgw_app_t sgw_app;

static void pcrf_exit(void);

static bool pcrf_lookup_context (
  const hash_key_t keyP,
  void * s_plus_p_gw_eps_bearer_context_information_v,
  void *ue_ip,
  void **context) {

  uint8_t i;
  uint32_t *ipv4_addr = (uint32_t*)ue_ip;
  struct s_plus_p_gw_eps_bearer_context_information_s* s_plus_p_gw_eps_bearer_context_information_p =
    (struct s_plus_p_gw_eps_bearer_context_information_s*)s_plus_p_gw_eps_bearer_context_information_v;

  sgw_eps_bearer_ctxt_t **sgw_eps_bearers = s_plus_p_gw_eps_bearer_context_information_p->sgw_eps_bearer_context_information.pdn_connection.sgw_eps_bearers_array;
  for(i = 0; i != BEARERS_PER_UE; i++) {
    if(sgw_eps_bearers[i] != NULL && sgw_eps_bearers[i]->paa.ipv4_address.s_addr == *ipv4_addr) {
      *context = s_plus_p_gw_eps_bearer_context_information_v;
      return true;
    }
  }

  *context = NULL;
  return false;
}


static void* pcrf_intertask_interface (void *args_p) {
  itti_mark_task_ready (TASK_PCRF);

  while (1) {
    MessageDef *received_message_p = NULL;
    itti_receive_msg (TASK_PCRF, &received_message_p);

    switch (ITTI_MSG_ID (received_message_p)) {

      case TERMINATE_MESSAGE:
        pcrf_exit();
        itti_exit_task ();
        break;

      case UDP_DATA_IND:
        OAILOG_DEBUG(LOG_PCRF, "Got UDP message.\n");

        udp_data_ind_t *udp_data_ind = &received_message_p->ittiMsg.udp_data_ind;

        if (udp_data_ind->buffer_length < 5){
          OAILOG_ERROR(LOG_PCRF, "Invalid PCRF controll message\n");
          break;
        }

        uint32_t ue_ip = *((uint32_t*)udp_data_ind->buffer);
        uint8_t sdf_id = *((uint8_t*)(udp_data_ind->buffer + sizeof(uint32_t)));
        OAILOG_DEBUG(LOG_PCRF, "Looking for SPGW context for IP: %u.%u.%u.%u and pushing %u SDF\n", NIPADDR(ue_ip), sdf_id);

        struct s_plus_p_gw_eps_bearer_context_information_s *s_plus_p_gw_eps_bearer_context_information_p = NULL;
        hashtable_ts_apply_callback_on_elements (
            sgw_app.s11_bearer_context_information_hashtable,
            pcrf_lookup_context,
            (void*)&ue_ip,
            (void**)&s_plus_p_gw_eps_bearer_context_information_p);

        if (s_plus_p_gw_eps_bearer_context_information_p == NULL) {
          OAILOG_ERROR(LOG_PCRF, "No context found\n");
          break;
        }

        OAILOG_DEBUG(LOG_PCRF, "Found SPGW context with TEID: %u", 
            s_plus_p_gw_eps_bearer_context_information_p->sgw_eps_bearer_context_information.s_gw_teid_S11_S4);
        sgw_no_pcef_create_dedicated_bearer(
            s_plus_p_gw_eps_bearer_context_information_p->sgw_eps_bearer_context_information.s_gw_teid_S11_S4,
            sdf_id);

        break;

      default:
        OAILOG_DEBUG (LOG_PCRF, "Unkwnon message ID %d:%s\n",
            ITTI_MSG_ID (received_message_p),
            ITTI_MSG_NAME (received_message_p));
        break;
    }

    itti_free_msg_content(received_message_p);
    itti_free (ITTI_MSG_ORIGIN_ID (received_message_p), received_message_p);
    received_message_p = NULL;
  }

  return NULL;
}

static int pcrf_send_init_udp (struct in_addr *address, uint16_t port_number) {
  MessageDef *message_p;
  message_p = itti_alloc_new_message (TASK_PCRF, UDP_INIT);

  if (message_p == NULL) {
    return RETURNerror;
  }

  message_p->ittiMsg.udp_init.port = port_number;
  message_p->ittiMsg.udp_init.address.s_addr = address->s_addr;
  char ipv4[INET_ADDRSTRLEN];
  inet_ntop (AF_INET, (void*)&message_p->ittiMsg.udp_init.address,
      ipv4, INET_ADDRSTRLEN);
  OAILOG_DEBUG (LOG_PCRF, "Tx UDP_INIT IP addr %s:%u\n", ipv4,
      message_p->ittiMsg.udp_init.port);
  return itti_send_msg_to_task (TASK_UDP, INSTANCE_DEFAULT, message_p);
}

int pcrf_init (sgw_config_t *config_p) {
  OAILOG_DEBUG (LOG_PCRF, "Initializing PCRF task interface\n");

  if (itti_create_task (TASK_PCRF, &pcrf_intertask_interface, NULL) < 0) {
    perror ("pthread_create");
    OAILOG_ALERT (LOG_PCRF, "Initializing PCRF task interface: ERROR\n");
    return RETURNerror;
  }

  pcrf_send_init_udp(&config_p->ipv4.S11, 22222);

  OAILOG_DEBUG (LOG_PCRF, "Initializing PCRF task interface: DONE\n");
  return RETURNok;
}

static void pcrf_exit(void) {
  OAI_FPRINTF_INFO("TASK_PCRF terminated");
}
