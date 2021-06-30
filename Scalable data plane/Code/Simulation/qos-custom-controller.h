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

#ifndef QOS_CUSTOM_CONTROLLER_H
#define QOS_CUSTOM_CONTROLLER_H

#include <ns3/ofswitch13-module.h>
#include <ns3/internet-module.h>
#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/lte-module.h>
#include "applications/svelte-client.h"

namespace ns3 {

class QosCustomController : public OFSwitch13Controller
{
public:

  // cookie masks for OpenFlow matching.
  #define COOKIE_STRICT_MASK  0xFFFFFFFFFFFFFFFF
  #define COOKIE_IPSRC_MASK   0xFFF0000000000000
  #define COOKIE_IPDST_MASK   0x000FFF0000000000
  #define COOKIE_PORTSRC_MASK 0x000000FFFF000000
  #define COOKIE_PORTDST_MASK 0x0000000000FFFF00
  #define COOKIE_PROTOCOL_MASK 0x00000000000000FF

  QosCustomController ();            //!< Default constructor.
  virtual ~QosCustomController ();   //!< Dummy destructor, see DoDispose.

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * Notify this controller of a new OpenFlow switch configured.
   * \param switchDevice The OpenFlow switch device.
   * \param ulPort The port connecting this switch to the UL switch.
   * \param dlPort The port connecting this switch to the DL switch.
   * \param hwPort The port connecting this switch to the HW switch.
   * \param swPort The port connecting this switch to the SW switch.
   */
  //\{
  void NotifyHwSwitch (Ptr<OFSwitch13Device> switchDevice, uint32_t ulPort, uint32_t dlPort);
  void NotifySwSwitch (Ptr<OFSwitch13Device> switchDevice, uint32_t ulPort, uint32_t dlPort);
  void NotifyUlSwitch (Ptr<OFSwitch13Device> switchDevice, uint32_t hwPort, uint32_t swPort);
  void NotifyDlSwitch (Ptr<OFSwitch13Device> switchDevice, uint32_t hwPort, uint32_t swPort);
  //\}

  /**
   * Creates the group rules for software switches 
   * \param switchDevice The openflow switch device
   * \param swports Switch ports
  */
  void CreateGroups (Ptr<OFSwitch13Device> switchDevice, 
                    std::vector<uint32_t> swports);

  /**
   * Notify this controller of a new host connected to the OpenFlow switch.
   * \param portNo The port number at the swithc.
   * \param ipAddr The host IP address.
   */
  //\{
  void NotifyDl2Sv (uint32_t portNo, Ipv4Address ipAddr);
  void NotifyUl2Sv (uint32_t portNo, Ipv4Address ipAddr);
  void NotifyUl2Cl (uint32_t portNo, Ipv4Address ipAddr);
  void NotifyDl2Cl (uint32_t portNo, Ipv4Address ipAddr);
  //\}

  /**
   * Notify this controller that all topology connections are done.
   */
  void NotifyTopologyBuilt ();

  /**
   * TracedCallback signature for request trace source.
   * \param teid The traffic ID.
   * \param accepted The traffic request status.
   */
  typedef void (*RequestTracedCallback)(uint32_t teid, bool accepted);

  /**
   * TracedCallback signature for release trace source.
   * \param teid The traffic ID.
   */
  typedef void (*ReleaseTracedCallback)(uint32_t teid);

  void imprimeSaida();  
  void PrintTrafficInfo();

protected:
  // Inherited from Object.
  virtual void DoDispose ();
  virtual void NotifyConstructionCompleted (void);

  // Inherited from OFSwitch13Controller.
  virtual void HandshakeSuccessful (Ptr<const RemoteSwitch> swtch);

private:
  /**
   * Stats timeout operation.
   */
  void StatsTimeout ();

  /**
   * Controller timeout operation.
   */
  void LoadControllerTimeout ();

  /**
   * Print SW load status.
   */
  void PrintLoadTimeout ();

  /**
   * Controller timeout operation.
   */
  void MoveTimeout ();

  /**
  * \param cookie The traffic cookie.
  */
  void MoveToSW (uint64_t cookie);

  /**
   * Install UDP traffic rules into OpenFlow switch.
   * \param switchDevice The OpenFlow switch for this traffic.
   * \param trafficId The traffic id.
   * \param group Ulink or Dlink group
   */
  void InstallUDPTrafficRules (Ptr<OFSwitch13Device> switchDevice, 
                               uint64_t trafficId, uint32_t group);

  /*
  * Increase the number of software switches active.
  */
  void IncreaseActiveSW ();

  /*
  * Decrease the number of software switches active.  
  */
  void DecreaseActiveSW ();

  /**
   * Install drop traffic rules into OpenFlow switch.
   * \param trafficId The traffic id.
   */
  void InstallDropRule (uint64_t trafficId);

  /**
   * Move traffic rules from one OpenFlow switch to another.
   * \param dstSwitchDevice The destination OpenFlow switch for this traffic.
   * \param trafficId The traffic id
  */
  void MoveTrafficRules (Ptr<OFSwitch13Device> dstSwitchDevice,
                         uint64_t trafficId);

  /**
   * Handle for removed messages
  */
  ofl_err HandleFlowRemoved (
    struct ofl_msg_flow_removed *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  ofl_err HandleError (
    struct ofl_msg_error *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  /**
   * Block check
  */
  bool CheckHwBlock();
  bool CheckSwBlock();
  bool CheckBlockStatus();

  /**
   * Handle packet-in messages sent from switch to this controller. Look for L2
   * switching information, update the structures and send a packet-out back.
   *
   * \param msg The packet-in message.
   * \param swtch The switch information.
   * \param xid Transaction id.
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err HandlePacketIn (
    struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  /**
   * Extract an IPv4 address from packet match.
   * \param oxm_of The OXM_IF_* IPv4 field.
   * \param match The ofl_match structure pointer.
   * \return The IPv4 address.
   */
  Ipv4Address ExtractIpv4Address (uint32_t oxm_of, struct ofl_match* match);

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

  //Traffic info struct
  struct trafficInfo{
    uint64_t cookie;
    Ipv4Address srcip;
    Ipv4Address dstip;
    uint16_t srcport;
    uint16_t dstport;
    uint16_t protocol;
    uint32_t numSwitches;
    bool active;
    bool inCache;
    bool blocked;
    uint32_t direction;
    std::string cmd;
    Time timeCreated;
    Time timeFinished;
    uint64_t bytes;
    uint64_t expBytes;
    DataRate rate;
  };
  //Map trafficId -> trafficInfo
  typedef std::map<uint64_t, struct trafficInfo> TrafficId_t;

  Ptr<OFSwitch13Device>           switchDeviceUl; //!< UL switch device.
  Ptr<OFSwitch13Device>           switchDeviceDl; //!< DL switch device.
  Ptr<OFSwitch13Device>           switchDeviceHw; //!< HW switch device.
  //Ptr<OFSwitch13Device>           switchDeviceSw; //!< SW switch device.
  OFSwitch13DeviceContainer       switchDevicesSw;

  uint32_t                        ul2hwPort;      //!< Porta no UL para o HW.
  uint32_t                        ul2swPort;      //!< Porta no UL para o SW.
  uint32_t                        dl2hwPort;      //!< Porta no DL para o HW.
  uint32_t                        dl2swPort;      //!< Porta no DL para o SW.

  uint64_t                        m_dpidUL;       //!< Datapath ID para o UL.
  uint64_t                        m_dpidDL;       //!< Datapath ID para o DL.
  //uint64_t                        m_dpidHW;       //!< Datapath ID para o HW.
  //uint64_t                        m_dpidSW;       //!< Datapath ID para o SW.

  uint64_t                        m_blocked;      //!< Numero de regras bloqueadas.
  uint64_t                        m_accepted;     //!< Numero de regras aceitas.
  uint64_t                        m_regrasAtivas; //!< Numero de regras ativas.
  Ptr<OutputStreamWrapper>        m_saida;        //!< Arquivo de regras bloqueadas.
  Ptr<OutputStreamWrapper>        m_log;          //!< Arquivo de log.
  Ptr<OutputStreamWrapper>        m_printTraffic; //!< Arquivo de saída da struct.
  Ptr<OutputStreamWrapper>        m_move;         //!< Arquivo de regras movidas.



  double                          m_blockThs;     //!< Threshold de bloqueio.
  bool                            m_blockPol;     //!< Política de bloqueio.
  bool                            m_qosRoute;     //!< Politica de roteamento.
  Time                            m_statsTimeout; //!< Timeout do controlador no modo Dinamico.
  Time                            m_moveTimeout;  //!< Timeout do controlador para mover regras SW->HW.
  Time                            m_loadTimeout;  //!< Timeout do controlador para verificar uso dos SW.
  Time                            m_newSwDelay;   //!< Tempo para instanciar um novo switch SW.
  std::map<uint32_t, Ipv4Address> m_teidAddr;     //!< Mapa TEID / IP cliente.
  TrafficId_t                     m_trafficInfo;  //!< Mapa TrafficID / TrafficInfo
  uint32_t                        m_activeSW;
  double                          m_minSwLoad;    //!< Limite minimo de carga nos switches SW.
  double                          m_maxSwLoad;    //!< Limite maximo de carga nos switches SW.
  uint32_t                        m_maxSW;


  TracedCallback<uint32_t, bool>  m_requestTrace; //!< Request trace source.
  TracedCallback<uint32_t>        m_releaseTrace; //!< Release trace source.

  /**
   * \name L2 switching structures
   */
  //\{
  /** L2SwitchingTable: map MacAddress to port */
  typedef std::map<Mac48Address, uint32_t> L2Table_t;

  /** Map datapathID to L2SwitchingTable */
  typedef std::map<uint64_t, L2Table_t> DatapathMap_t;

  /** Switching information for all dapataths */
  DatapathMap_t m_learnedInfo;
  //\}
};

} // namespace ns3
#endif  // QOS_CUSTOM_CONTROLLER_H
