/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2020 University of Juiz de Fora (UFJF)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: João Victor Guimarães de Oliveira <joaoguimaraes@ice.ufjf.br>
 *         Pedro Clemente Pereira Bellotti <pedro.bellotti@ice.ufjf.br>
 *         Roberto Massi de Oliveira <rmassi@ice.ufjf.br>
 *         Alex Borges Vieira <alex.borges@ice.ufjf.br>
 *         Luciano J. Chaves <luciano.chaves@ice.ufjf.br>
 */

#ifndef TRAFFIC_HELPER_H
#define TRAFFIC_HELPER_H

#include <ns3/core-module.h>
#include <ns3/lte-module.h>
#include <ns3/network-module.h>
#include <ns3/internet-module.h>
#include "application-helper.h"

namespace ns3 {

//class CustomController;
class QosCustomController;
class TrafficManager;

/**
 * \ingroup svelte
 * Traffic helper which installs client and server applications for all
 * applications into UEs and WebServer. This helper creates and aggregates a
 * traffic manager for each UE.
 */
class TrafficHelper : public Object
{
public:
  /**
   * Complete constructor.
   * \param controller The OpenFlow controller.
   * \param webNode The server node.
   * \param ueNodes The client nodes.
   */
  TrafficHelper (Ptr<QosCustomController> controller,
                 NodeContainer webNodes, NodeContainer ueNodes);
  virtual ~TrafficHelper ();  //!< Dummy destructor, see DoDispose.

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

protected:
  /** Destructor implementation. */
  virtual void DoDispose ();

  // Inherited from ObjectBase
  void NotifyConstructionCompleted (void);

private:
  /**
   * Install a traffic manager into each UE and configure the EPS bearers and
   * TFT packet filters for enable applications
   * \attention The QCIs used here for each application are strongly related to
   *     the DSCP mapping, which will reflect on the priority queues used by
   *     both OpenFlow switches and traffic control module. Be careful if you
   *     intend to change it.
   * \internal Some notes about internal GbrQosInformation usage:
   * \li The Maximum Bit Rate field is used by controller to install meter
   *     rules for this traffic. When this value is left to 0, no meter rules
   *     will be installed.
   * \li The Guaranteed Bit Rate field is used by the controller to reserve the
   *     requested bandwidth in OpenFlow EPC network (only for GBR beares).
   */
  void ConfigureApplications ();

  /**
   * Configure application helpers for different traffic patterns.
   */
  void ConfigureHelpers ();

  /**
   * Get the next port number available for use.
   * \return The port number to use.
   */
  static uint16_t GetNextPortNo ();

  /**
   * Create the pair of client/server applications and install them into UE,
   * using the default EPS bearer for this traffic.
   * \param helper The reference to the application helper.
   * \param teid The TEID for this application.
   */
  void InstallAppDefault (ApplicationHelper& helper, uint64_t teid);

  /**
   * Create a intelligent cookie.
   * \param ipsrc The IP source.
   * \param ipdst The IP destination.
   * \param portsrc The port source.
   * \param portdst The port destination.
   * \param protocol Protocol.
   * \param teid The ID from the traffic.
   * \return The cookie created.
   *
   * Cookie has 64 bits length: 0x 000 000 0000 0000 00
   *                              |---|---|----|----|--|
   *                               A   B  C    D   E
   * 12 (A) bits are used to identify the IP SCR.
   * 12 (B) bits are used to identify the IP DST.
   * 16 (C) bits are used to identify the port src.
   * 16 (D) bits are used to identify the port dst.
   * 8 (E) bits are used to identify the protocol.
   */
  uint64_t CookieCreate (Ipv4Address ipsrc, Ipv4Address ipdst, uint16_t portsrc, uint16_t portdst, uint8_t protocol);

  // Traffic helper.
  Ptr<QosCustomController>    m_controller;       //!< OpenFlow controller.
  static uint16_t             m_port;             //!< Port numbers for apps.
  uint32_t                    m_pingTracked;      //!< Number of apps with tracked ping.


  // Traffic manager.
  ObjectFactory               m_managerFac;       //!< Traffic manager factory.
  Ptr<RandomVariableStream>   m_poissonRng;       //!< Inter-arrival traffic.
  bool                        m_restartApps;      //!< Continuous restart apps.
  Time                        m_startAppsAt;      //!< Time to start apps.
  Time                        m_stopAppsAt;       //!< Time to stop apps.

  // Enabled applications.
  bool                        m_gbrVoipCall;      //!< GBR VoIP call.

  // Application helpers.
  ApplicationHelper           m_voipCallHelper;   //!< VoIP call helper.

  // Temporary variables used only when installing applications.
  NodeContainer               m_ueNodes;          //!< Client nodes.
  NodeContainer               m_webNodes;         //!< Server nodes.
  Ptr<Node>                   t_webNode;          //!< Server node.
  Ipv4Address                 t_webAddr;          //!< Server address.
  Ptr<TrafficManager>         t_ueManager;        //!< Traffic manager.
  Ptr<Node>                   t_ueNode;           //!< Client node.
  Ipv4Address                 t_ueAddr;           //!< Client address.

};

} // namespace ns3
#endif // TRAFFIC_HELPER_H
