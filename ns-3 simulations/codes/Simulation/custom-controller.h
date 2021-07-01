/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2018 University of Campinas (Unicamp)
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
 * Author: Rafael G. Motta <rafaelgmotta@gmail.com>
 *         Luciano J. Chaves <ljerezchaves@gmail.com>
 */

#ifndef CUSTOM_CONTROLLER_H
#define CUSTOM_CONTROLLER_H

#include <ns3/ofswitch13-module.h>
#include <ns3/internet-module.h>
#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/lte-module.h>
#include "applications/svelte-client.h"

namespace ns3 {

class CustomController : public OFSwitch13Controller
{
public:
  CustomController ();            //!< Default constructor.
  virtual ~CustomController ();   //!< Dummy destructor, see DoDispose.

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

protected:
  // Inherited from Object.
  virtual void DoDispose ();
  virtual void NotifyConstructionCompleted (void);

  // Inherited from OFSwitch13Controller.
  virtual void HandshakeSuccessful (Ptr<const RemoteSwitch> swtch);

private:
  /**
   * Controller timeout operation.
   */
  void ControllerTimeout ();
  void QoSControllerTimeout ();

  /**
   * Install UDP traffic rules into OpenFlow switch.
   * \param switchDevice The OpenFlow switch for this traffic.
   * \param trafficId The traffic id.
   * \param modify If the rule is being added or modified
   * \param group Ulink or Dlink group
   */
  void InstallUDPTrafficRules (Ptr<OFSwitch13Device> switchDevice, 
                               uint32_t trafficId, bool modify,
                               uint32_t group);

  /**
   * Install drop traffic rules into OpenFlow switch.
   * \param switchDevice The OpenFlow switch for this traffic.
   * \param trafficId The traffic id.
   */
  void InstallDropRule (Ptr<OFSwitch13Device> switchDevice,
                        uint32_t trafficId);

  /**
   * Remove traffic rules from OpenFlow switch.
   * \param switchDevice The OpenFlow switch for this traffic.
   * \param port The traffic ID.
   */
  void RemoveTrafficRules (Ptr<OFSwitch13Device> switchDevice, uint32_t port);

  /**
   * Move traffic rules from one OpenFlow switch to another.
   * \param srcSwitchDevice The source OpenFlow switch for this traffic.
   * \param dstSwitchDevice The destination OpenFlow switch for this traffic.
   * \param trafficId The traffic id
  */
  void MoveTrafficRules (Ptr<OFSwitch13Device> srcSwitchDevice,
                         Ptr<OFSwitch13Device> dstSwitchDevice,
                         uint32_t trafficId);

  /**
   * Update UL and DL rules when moving traffic.
   * \param cookie The traffic cookie.
  */
  void UpdateDlUlRules (uint32_t cookie);

  /**
   * Handle for removed messages
  */
  ofl_err HandleFlowRemoved (
    struct ofl_msg_flow_removed *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

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

  //Traffic info struct
  struct trafficInfo{
    Ipv4Address srcip;
    Ipv4Address dstip;
    uint16_t srcport;
    uint16_t dstport;
    uint16_t protocol;
  };
  //Map trafficId -> trafficInfo
  typedef std::map<uint32_t, struct trafficInfo> TrafficId_t;

  Ptr<OFSwitch13Device>           switchDeviceUl; //!< UL switch device.
  Ptr<OFSwitch13Device>           switchDeviceDl; //!< DL switch device.
  Ptr<OFSwitch13Device>           switchDeviceHw; //!< HW switch device.
  Ptr<OFSwitch13Device>           switchDeviceSw; //!< SW switch device.

  uint32_t                        ul2hwPort;      //!< Porta no UL para o HW.
  uint32_t                        ul2swPort;      //!< Porta no UL para o SW.
  uint32_t                        dl2hwPort;      //!< Porta no DL para o HW.
  uint32_t                        dl2swPort;      //!< Porta no DL para o SW.
  uint32_t                        hw2ulPort;      //!< Porta no HW para o UL.
  uint32_t                        hw2dlPort;      //!< Porta no HW para o DL.
  uint32_t                        sw2ulPort;      //!< Porta no SW para o UL.
  uint32_t                        sw2dlPort;      //!< Porta no SW para o DL.

  uint64_t                        m_dpidUL;       //!< Datapath ID para o UL.
  uint64_t                        m_dpidDL;       //!< Datapath ID para o DL.
  uint64_t                        m_dpidHW;       //!< Datapath ID para o HW.
  uint64_t                        m_dpidSW;       //!< Datapath ID para o SW.

  uint64_t                        m_blocked;    //!< Numero de regras bloqueadas.
  uint64_t                        m_accepted;    //!< Numero de regras aceitas.
  Ptr<OutputStreamWrapper>        m_saida;        //!< Arquivo de regras bloqueadas.

  uint32_t                        m_regrasHw;     //!< Numero de regras instaladas no switch HW.
  double                          m_blockThs;     //!< Threshold de bloqueio.
  bool                            m_blockPol;     //!< Política de bloqueio.
  bool                            m_qosRoute;     //!< Politica de roteamento.
  Time                            m_qosTimeout;   //!< Timeout do controlador no modo Dinamico.
  Time                            m_estTimeout;   //!< Timeout do controlador no modo Estatico.
  std::map<uint32_t, Ipv4Address> m_teidAddr;     //!< Mapa TEID / IP cliente.
  TrafficId_t                     m_trafficInfo;  //!< Mapa TrafficID / TrafficInfo
  uint32_t                        m_trafficId;

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
#endif  // CUSTOM_CONTROLLER_H
