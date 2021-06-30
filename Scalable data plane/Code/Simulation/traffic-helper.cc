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

#include "traffic-helper.h"
#include "applications/svelte-udp-client.h"
#include "applications/svelte-udp-server.h"
#include "applications/app-stats-calculator.h"
#include "qos-custom-controller.h"
#include "traffic-manager.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("TrafficHelper");
NS_OBJECT_ENSURE_REGISTERED (TrafficHelper);

// Initial port number
uint16_t TrafficHelper::m_port = 10000;

// ------------------------------------------------------------------------ //
TrafficHelper::TrafficHelper (Ptr<QosCustomController> controller,
                              NodeContainer webNodes, NodeContainer ueNodes)
{
  NS_LOG_FUNCTION (this);

  m_controller = controller;
  m_webNodes = webNodes;
  m_ueNodes = ueNodes;
  m_pingTracked = 0;
}

TrafficHelper::~TrafficHelper ()
{
  NS_LOG_FUNCTION (this);
}

TypeId
TrafficHelper::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TrafficHelper")
    .SetParent<Object> ()

    // Traffic manager attributes.
    .AddAttribute ("PoissonInterArrival",
                   "An exponential random variable used to get "
                   "application inter-arrival start times.",
                   TypeId::ATTR_GET | TypeId::ATTR_CONSTRUCT,
                   StringValue ("ns3::ExponentialRandomVariable[Mean=2.0]"),
                   MakePointerAccessor (&TrafficHelper::m_poissonRng),
                   MakePointerChecker <RandomVariableStream> ())
    .AddAttribute ("RestartApps",
                   "Continuously restart applications after stop events.",
                   TypeId::ATTR_GET | TypeId::ATTR_CONSTRUCT,
                   BooleanValue (false),
                   MakeBooleanAccessor (&TrafficHelper::m_restartApps),
                   MakeBooleanChecker ())
    .AddAttribute ("StartAppsAt",
                   "The time to start the applications.",
                   TimeValue (Seconds (1)),
                   MakeTimeAccessor (&TrafficHelper::m_startAppsAt),
                   MakeTimeChecker (Seconds (1)))
    .AddAttribute ("StopAppsAt",
                   "The time to stop the applications.",
                   TimeValue (Seconds (0)),
                   MakeTimeAccessor (&TrafficHelper::m_stopAppsAt),
                   MakeTimeChecker (Time (0)))

    // Applications to be installed.
    .AddAttribute ("EnableGbrVoipCall",
                   "Enable GBR VoIP call traffic.",
                   TypeId::ATTR_GET | TypeId::ATTR_CONSTRUCT,
                   BooleanValue (true),
                   MakeBooleanAccessor (&TrafficHelper::m_gbrVoipCall),
                   MakeBooleanChecker ())
  ;
  return tid;
}

void
TrafficHelper::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  m_poissonRng = 0;
  t_webNode = 0;
  t_ueManager = 0;
  t_ueNode = 0;
  Object::DoDispose ();
}

void
TrafficHelper::NotifyConstructionCompleted ()
{
  NS_LOG_FUNCTION (this);

  /* Saving server metadata.
  NS_ASSERT_MSG (m_webNode->GetNDevices () == 2, "Single device expected.");
  Ptr<NetDevice> webDev = m_webNode->GetDevice (1);

  Ptr<Ipv4> ipv4 = m_webNode->GetObject<Ipv4> ();
  int32_t ifIndex = ipv4->GetInterfaceForDevice (webDev);
  m_webAddr = ipv4->GetAddress (ifIndex, 0).GetLocal ();*/

  // Configure the traffic manager object factory.
  m_managerFac.SetTypeId (TrafficManager::GetTypeId ());
  m_managerFac.Set ("PoissonInterArrival", PointerValue (m_poissonRng));
  m_managerFac.Set ("RestartApps", BooleanValue (m_restartApps));
  m_managerFac.Set ("StartAppsAt", TimeValue (m_startAppsAt));
  m_managerFac.Set ("StopAppsAt", TimeValue (m_stopAppsAt));

  // Configure the helpers and install the applications.
  ConfigureHelpers ();
  ConfigureApplications ();

  Object::NotifyConstructionCompleted ();
}

void
TrafficHelper::ConfigureHelpers ()
{
  NS_LOG_FUNCTION (this);

  // -------------------------------------------------------------------------
  // Configuring HTC application helpers.

  //
  // The VoIP application with the G.729 codec.
  //
  m_voipCallHelper = ApplicationHelper (SvelteUdpClient::GetTypeId (),
                                        SvelteUdpServer::GetTypeId ());
  m_voipCallHelper.SetClientAttribute ("AppName", StringValue ("VoipCall"));

  // Traffic length: we are considering an estimative from Vodafone that
  // the average call length is 1 min and 40 sec with a 10 sec stdev, See
  // http://tinyurl.com/pzmyys2 and https://tinyurl.com/yceqtej9 for details.
  m_voipCallHelper.SetClientAttribute (
    "TrafficLength",
    StringValue ("ns3::UniformRandomVariable[Min=5.0|Max=100.0]"));

  // Traffic model: 20B packets sent in both directions every 0.02 seconds.
  // Check http://goo.gl/iChPGQ for bandwidth calculation and discussion.
  m_voipCallHelper.SetClientAttribute (
    "PktSize",
    UintegerValue (1458)); //Tamanho pacote do Iperf (1458+12 (cabecalho) = 1470)
  m_voipCallHelper.SetClientAttribute (
    "DataRate",
    StringValue ("ns3::ExponentialRandomVariable[Mean=1024]"));
  m_voipCallHelper.SetServerAttribute (
    "PktSize",
    UintegerValue (1458));
  m_voipCallHelper.SetServerAttribute (
    "PktInterval",
    StringValue ("ns3::ConstantRandomVariable[Constant=9999999]"));
}

void
TrafficHelper::ConfigureApplications ()
{
  NS_LOG_FUNCTION (this);

  // Install traffic manager and applications into UE nodes.
  for (uint32_t u = 0; u < m_ueNodes.GetN (); u++)
    {
      uint64_t ueImsi = u << 16;

      t_webNode = m_webNodes.Get (u);
      Ptr<Ipv4> serverIpv4 = t_webNode->GetObject<Ipv4> ();
      t_webAddr = serverIpv4->GetAddress (1, 0).GetLocal ();

      t_ueNode = m_ueNodes.Get (u);
      Ptr<Ipv4> clientIpv4 = t_ueNode->GetObject<Ipv4> ();
      t_ueAddr = clientIpv4->GetAddress (1, 0).GetLocal ();

      // Each UE gets one traffic manager.
      t_ueManager = m_managerFac.Create<TrafficManager> ();
      t_ueManager->SetController (m_controller);
      t_ueManager->SetImsi (ueImsi);
      t_ueNode->AggregateObject (t_ueManager);

      // Install enabled applications into this UE.
      // UDP Apps
      //
      // VoIP call
      if (m_gbrVoipCall)
      {
        for (uint32_t v = 0; v < 250; v++)
          InstallAppDefault (m_voipCallHelper, ueImsi + v);
      }
    }
  t_ueManager = 0;
  t_ueNode = 0;
  t_webNode = 0;
}

uint16_t
TrafficHelper::GetNextPortNo ()
{
  NS_ABORT_MSG_IF (m_port == 0xFFFF, "No more ports available for use.");
  return m_port++;
}

uint64_t
TrafficHelper::CookieCreate (Ipv4Address ipsrc, Ipv4Address ipdst, uint16_t portsrc, uint16_t portdst, uint8_t protocol)
{
  Ipv4Mask mask ("255.255.240.0");

  uint64_t cookie = 0x0;
  cookie |= ipsrc.CombineMask(mask.GetInverse()).Get();
  cookie <<= 12;
  cookie |= ipdst.CombineMask(mask.GetInverse()).Get();
  cookie <<= 16;
  cookie |= portsrc;
  cookie <<= 16;
  cookie |= portdst;
  cookie <<= 8;
  cookie |= protocol;

  return cookie;
}

void
TrafficHelper::InstallAppDefault (ApplicationHelper& helper, uint64_t teid)
{
  NS_LOG_FUNCTION (this);

  // Create the client and server applications.
  uint16_t clientport = 10000 + teid;
  uint16_t serverport = 30000 + teid;
  Ptr<SvelteClient> clientApp = helper.Install (
      t_ueNode, t_webNode, t_ueAddr, t_webAddr, clientport, serverport);
  //std::cout<<"instalando cliente ip "<< t_ueAddr <<" no server ip"<< t_webAddr << std::endl;
  uint64_t cookie = CookieCreate(t_ueAddr, t_webAddr, clientport, serverport, IP_TYPE_UDP);
  clientApp->SetTeid (cookie);
  //clientApp->SetTeid (teid);
  t_ueManager->AddSvelteClient (clientApp);
}

} // namespace ns3
