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

#include "custom-controller.h"
#include "applications/svelte-client.h"
#include <algorithm>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <ns3/ofswitch13-module.h>
#include <set>

using namespace std;

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("CustomController");
NS_OBJECT_ENSURE_REGISTERED (CustomController);

CustomController::CustomController ()
{
  NS_LOG_FUNCTION (this);
  m_blocked = 0;
  m_accepted = 0;
  m_regrasHw = 3; //2 regras ping + regra padrao de enviar para o controlador
  m_trafficId = 1000;
}

CustomController::~CustomController ()
{
  NS_LOG_FUNCTION (this);
}

TypeId
CustomController::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::CustomController")
    .SetParent<OFSwitch13Controller> ()
    .AddConstructor<CustomController> ()
    .AddAttribute ("BlockThs",
                   "Switch overloaded block threshold.",
                   DoubleValue (1.0),
                   MakeDoubleAccessor (&CustomController::m_blockThs),
                   MakeDoubleChecker<double> (0.8, 1.0))
    .AddAttribute ("BlockPolicy",
                   "Switch overloaded block policy (true for block).",
                   BooleanValue (true),
                   MakeBooleanAccessor (&CustomController::m_blockPol),
                   MakeBooleanChecker ())
    .AddAttribute ("SmartRouting",
                   "True for QoS routing, false for IP routing.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&CustomController::m_qosRoute),
                   MakeBooleanChecker ())
    .AddAttribute ("QosTimeout",
                   "Controller timeout interval in QoS mode.",
                   TimeValue (Seconds (10)),
                   MakeTimeAccessor (&CustomController::m_qosTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("EstTimeout",
                   "Controller timeout interval in static mode.",
                   TimeValue (Seconds (5)),
                   MakeTimeAccessor (&CustomController::m_estTimeout),
                   MakeTimeChecker ())

    .AddTraceSource ("Request", "The request trace source.",
                     MakeTraceSourceAccessor (&CustomController::m_requestTrace),
                     "ns3::CustomController::RequestTracedCallback")
    .AddTraceSource ("Release", "The release trace source.",
                     MakeTraceSourceAccessor (&CustomController::m_releaseTrace),
                     "ns3::CustomController::ReleaseTracedCallback")
  ;
  return tid;
}

void
CustomController::NotifyHwSwitch (Ptr<OFSwitch13Device> switchDevice,
                                  uint32_t ulPort, uint32_t dlPort)
{
  NS_LOG_FUNCTION (this << switchDevice << ulPort << dlPort);

  // Salvando switch e número de portas.
  switchDeviceHw = switchDevice;
  hw2dlPort = dlPort;
  hw2ulPort = ulPort;
  m_dpidHW = switchDeviceHw->GetDatapathId ();

  // Neste switch estamos configurando dois grupos:
  // Grupo 1, usado para enviar pacotes na direção de uplink.
  // Grupo 2, usado para enviar pacotes na direção de downlink.
  std::ostringstream cmd1, cmd2;
  cmd1 << "group-mod cmd=add,type=ind,group=1"
       << " weight=0,port=any,group=any"
       << " output=" << hw2dlPort;

  cmd2 << "group-mod cmd=add,type=ind,group=2"
       << " weight=0,port=any,group=any"
       << " output=" << hw2ulPort;

  DpctlExecute (switchDeviceHw->GetDatapathId (), cmd1.str ());
  DpctlExecute (switchDeviceHw->GetDatapathId (), cmd2.str ());
}

void
CustomController::NotifySwSwitch (Ptr<OFSwitch13Device> switchDevice,
                                  uint32_t ulPort, uint32_t dlPort)
{
  NS_LOG_FUNCTION (this << switchDevice << ulPort << dlPort);

  // Salvando switch e número de portas.
  switchDeviceSw = switchDevice;
  sw2dlPort = dlPort;
  sw2ulPort = ulPort;
  m_dpidSW = switchDeviceSw->GetDatapathId ();

  // Neste switch estamos configurando dois grupos:
  // Grupo 1, usado para enviar pacotes na direção de uplink.
  // Grupo 2, usado para enviar pacotes na direção de downlink.
  std::ostringstream cmd1, cmd2;
  cmd1 << "group-mod cmd=add,type=ind,group=1"
       << " weight=0,port=any,group=any"
       << " output=" << sw2dlPort;

  cmd2 << "group-mod cmd=add,type=ind,group=2"
       << " weight=0,port=any,group=any"
       << " output=" << sw2ulPort;

  DpctlExecute (switchDeviceSw->GetDatapathId (), cmd1.str ());
  DpctlExecute (switchDeviceSw->GetDatapathId (), cmd2.str ());
}

void
CustomController::NotifyUlSwitch (Ptr<OFSwitch13Device> switchDevice,
                                  uint32_t hwPort, uint32_t swPort)
{
  NS_LOG_FUNCTION (this << switchDevice << hwPort << swPort);

  // Salvando switch e número de portas.
  switchDeviceUl = switchDevice;
  ul2hwPort = hwPort;
  ul2swPort = swPort;
  m_dpidUL = switchDeviceUl->GetDatapathId ();
}

void
CustomController::NotifyDlSwitch (Ptr<OFSwitch13Device> switchDevice,
                                  uint32_t hwPort, uint32_t swPort)
{
  NS_LOG_FUNCTION (this << switchDevice << hwPort << swPort);

  // Salvando switch e número de portas.
  switchDeviceDl = switchDevice;
  dl2hwPort = hwPort;
  dl2swPort = swPort;
  m_dpidDL = switchDeviceDl->GetDatapathId ();
}

void
CustomController::NotifyDl2Sv (uint32_t portNo, Ipv4Address ipAddr)
{
  NS_LOG_FUNCTION (this << portNo << ipAddr);

  // Inserindo na tabela 0 a regra que mapeia IP de destino na porta de saída.
  std::ostringstream cmd;
  cmd << "flow-mod cmd=add,prio=64,table=0"
      << " eth_type=0x800,ip_dst=" << ipAddr
      << " apply:output=" << portNo;
  DpctlExecute (switchDeviceDl->GetDatapathId (), cmd.str ());
}

void
CustomController::NotifyUl2Sv (uint32_t portNo, Ipv4Address ipAddr)
{
  NS_LOG_FUNCTION (this << portNo << ipAddr);

  // Inserindo na tabela 0 a regra que mapeia IP de destino na porta de saída.
  std::ostringstream cmd;
  cmd << "flow-mod cmd=add,prio=64,table=0"
      << " eth_type=0x800,ip_dst=" << ipAddr
      << " apply:output=" << portNo;
  DpctlExecute (switchDeviceUl->GetDatapathId (), cmd.str ());
}

void
CustomController::NotifyDl2Cl (uint32_t portNo, Ipv4Address ipAddr)
{
  NS_LOG_FUNCTION (this << portNo << ipAddr);

  // Inserindo na tabela 0 a regra que mapeia IP de destino na porta de saída.
  std::ostringstream cmd;
  cmd << "flow-mod cmd=add,prio=64,table=0"
      << " eth_type=0x800,ip_dst=" << ipAddr
      << " apply:output=" << portNo;
  DpctlExecute (switchDeviceDl->GetDatapathId (), cmd.str ());
}

void
CustomController::NotifyUl2Cl (uint32_t portNo, Ipv4Address ipAddr)
{
  NS_LOG_FUNCTION (this << portNo << ipAddr);

  // Inserindo na tabela 0 a regra que mapeia IP de destino na porta de saída.
  std::ostringstream cmd;
  cmd << "flow-mod cmd=add,prio=64,table=0"
      << " eth_type=0x800,ip_dst=" << ipAddr
      << " apply:output=" << portNo;
  DpctlExecute (switchDeviceUl->GetDatapathId (), cmd.str ());
}

void
CustomController::NotifyTopologyBuilt ()
{
  NS_LOG_FUNCTION (this);

  //Instala a regra de ping no switch HW
  std::ostringstream cmdUlink , cmdDlink;
  cmdUlink << "flow-mod cmd=add,prio=128,table=0,cookie=" << GetUint32Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_src=" << 65534 << ",udp_dst=" << 7000;
  cmdDlink << "flow-mod cmd=add,prio=128,table=0,cookie=" << GetUint32Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_dst=" << 65534 << ",udp_src=" << 7000;
  // Saidas de Uplink/Downlink.
  cmdUlink << " write:group=1";
  cmdDlink << " write:group=2";
  DpctlExecute (switchDeviceHw->GetDatapathId (), cmdUlink.str ());
  DpctlExecute (switchDeviceHw->GetDatapathId (), cmdDlink.str ());

  //Instala a regra de ping no switch SW
  std::ostringstream cmdUlinkSW , cmdDlinkSW;
  cmdUlinkSW << "flow-mod cmd=add,prio=228,table=0,cookie=" << GetUint32Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_src=" << 65535 << ",udp_dst=" << 7001;
  cmdDlinkSW << "flow-mod cmd=add,prio=228,table=0,cookie=" << GetUint32Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_dst=" << 65535 << ",udp_src=" << 7001;
  // Saidas de Uplink/Downlink.
  cmdUlinkSW << " write:group=1";
  cmdDlinkSW << " write:group=2";
  DpctlExecute (switchDeviceSw->GetDatapathId (), cmdUlinkSW.str ());
  DpctlExecute (switchDeviceSw->GetDatapathId (), cmdDlinkSW.str ());

  // Instala a regra de ping nos switches UL e DL
  //HW
  std::ostringstream cmdUL , cmdDL;
  cmdUL << "flow-mod cmd=add,prio=128,table=0,cookie=" << GetUint32Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_src=" << 65534 << ",udp_dst=" << 7000;
  cmdDL << "flow-mod cmd=add,prio=128,table=0,cookie=" << GetUint32Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_dst=" << 65534 << ",udp_src=" << 7000;
  // Saidas de Uplink/Downlink.
  cmdUL << " apply:output="<< ul2hwPort;
  cmdDL << " apply:output=" << dl2hwPort;
  DpctlExecute (switchDeviceUl->GetDatapathId (), cmdUL.str ());
  DpctlExecute (switchDeviceDl->GetDatapathId (), cmdDL.str ());

  //SW
  std::ostringstream cmdULSW , cmdDLSW;
  cmdULSW << "flow-mod cmd=add,prio=228,table=0,cookie=" << GetUint32Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_src=" << 65535 << ",udp_dst=" << 7001;
  cmdDLSW << "flow-mod cmd=add,prio=228,table=0,cookie=" << GetUint32Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_dst=" << 65535 << ",udp_src=" << 7001;
  // Saidas de Uplink/Downlink.
  cmdULSW << " apply:output="<< ul2swPort;
  cmdDLSW << " apply:output=" << dl2swPort;
  DpctlExecute (switchDeviceUl->GetDatapathId (), cmdULSW.str ());
  DpctlExecute (switchDeviceDl->GetDatapathId (), cmdDLSW.str ());
}

void
CustomController::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  switchDeviceUl = 0;
  switchDeviceDl = 0;
  switchDeviceHw = 0;
  switchDeviceSw = 0;
  m_saida = 0;
  m_teidAddr.clear ();
  OFSwitch13Controller::DoDispose ();
}

void
CustomController::NotifyConstructionCompleted (void)
{
  NS_LOG_FUNCTION (this);
  StringValue stringValue;
  GlobalValue::GetValueByName ("OutputPrefix", stringValue);
  std::string prefix = stringValue.Get ();
  m_saida = Create<OutputStreamWrapper> (prefix+"regrasBloqueadas.txt", std::ios::out); 
  // Print the header in output file.
  *m_saida->GetStream ()
    << boolalpha << right << fixed << setprecision (3)
    << setw (8)  << "Time"
    << " " << setw (8)  << "RegrasAceitas"
    << " " << setw (8)  << "RegrasBloqueadas"
    << std::endl;

  // Escalona a primeira operação de timeout para o controlador.
  if(m_qosRoute)
  {
    Simulator::Schedule (m_qosTimeout, &CustomController::QoSControllerTimeout, this);
  }
  else
  {
    Simulator::Schedule (m_estTimeout, &CustomController::ControllerTimeout, this);
  }
  Simulator::Schedule (Seconds(1), &CustomController::imprimeSaida, this);
  OFSwitch13Controller::NotifyConstructionCompleted ();
}

void
CustomController::imprimeSaida(){
  *m_saida->GetStream ()
    << setw (8) << Simulator::Now().GetSeconds()
    << " " << setw (8) << m_accepted
    << " " << setw (8) << m_blocked
    << std::endl;
  Simulator::Schedule (Seconds(1), &CustomController::imprimeSaida, this);
}

Ipv4Address
CustomController::ExtractIpv4Address (uint32_t oxm_of, struct ofl_match* match)
{
  switch (oxm_of)
    {
    case OXM_OF_ARP_SPA:
    case OXM_OF_ARP_TPA:
    case OXM_OF_IPV4_DST:
    case OXM_OF_IPV4_SRC:
      {
        uint32_t ip;
        int size = OXM_LENGTH (oxm_of);
        struct ofl_match_tlv *tlv = oxm_match_lookup (oxm_of, match);
        memcpy (&ip, tlv->value, size);
        return Ipv4Address (ntohl (ip));
      }
    default:
      NS_ABORT_MSG ("Invalid IP field.");
    }
}

ofl_err
CustomController::HandlePacketIn (
  struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  /*char *msgStr = ofl_structs_match_to_string ((struct ofl_match_header*)msg->match, 0);
  NS_LOG_INFO ("Packet in match: " << msgStr);
  free (msgStr);*/

  if (msg->reason == OFPR_NO_MATCH)
  {
    //Identificando grupo (ulink ou dlink)
    uint32_t group = 0;
    if (swtch->GetDpId() == m_dpidUL)
    {
      group = 1;
    }
    else if (swtch->GetDpId() == m_dpidDL)
    {
      group = 2;
    }
    size_t len = 0;
    struct ofl_match_tlv *input = NULL;
    uint32_t packetoutport = 0;
    bool drop = false;

    //UDP SRC
    uint16_t udp_src;
    len = OXM_LENGTH (OXM_OF_UDP_SRC);
    input = oxm_match_lookup (OXM_OF_UDP_SRC, (struct ofl_match*)msg->match);
    memcpy (&udp_src, input->value, len);

    //Porta fisica
    uint32_t inPort;
    len = OXM_LENGTH (OXM_OF_IN_PORT);
    input = oxm_match_lookup (OXM_OF_IN_PORT, (struct ofl_match*)msg->match);
    memcpy (&inPort, input->value, len);

    //UDP DST
    uint16_t udp_dst;
    len = OXM_LENGTH (OXM_OF_UDP_DST);
    input = oxm_match_lookup (OXM_OF_UDP_DST, (struct ofl_match*)msg->match);
    memcpy (&udp_dst, input->value, len);

    //IP src/dst
    Ipv4Address srcIp, dstIp;
    srcIp = ExtractIpv4Address (OXM_OF_IPV4_SRC, (struct ofl_match*)msg->match);
    dstIp = ExtractIpv4Address (OXM_OF_IPV4_DST, (struct ofl_match*)msg->match);

    //Adiciona informacoes na struct
    struct trafficInfo info;
    info.srcip = srcIp;
    info.dstip = dstIp;
    info.srcport = udp_src;
    info.dstport = udp_dst;
    info.protocol = IP_TYPE_UDP;

    //Mapa
    m_trafficId++;
    uint32_t newId = m_trafficId;
    std::pair<uint32_t, struct trafficInfo> entry (newId, info);
    m_trafficInfo.insert(entry);
    NS_LOG_DEBUG("New traffic ID: " << newId);
   
    //Politicas
    if(m_qosRoute)
    {
      //Instala tudo no SW
      if (group == 1)
      {
        packetoutport = ul2swPort;
      }
      else
      {
        packetoutport = dl2swPort;
      }
      InstallUDPTrafficRules(switchDeviceSw, newId, false, group);
      m_accepted += 1;
    }
    else
    {
      //Porta par, instala no switch HW
      if(udp_src % 2 == 0)
      {
        //Antes de instalar no HW, verifica se ele tem espaco na tabela
        if (m_regrasHw+1 > switchDeviceHw->GetFlowTableSize(0)) //+1 porque precisamos instalar 1 regra
        { // Bloquear o tráfego se a tabela exceder o limite de bloqueio.
          m_requestTrace (udp_src, false);
          if (group == 1)
          {
            InstallDropRule(switchDeviceUl, newId);
          }
          else
          {
            InstallDropRule(switchDeviceDl, newId);
          }
          drop = true;
          m_blocked +=1;
        }
        else
        {
          if (group == 1)
          {
            packetoutport = ul2hwPort;
          }
          else
          {
            packetoutport = dl2hwPort;
          }
          InstallUDPTrafficRules(switchDeviceHw, newId, false, group);
          m_regrasHw += 1;
          m_accepted += 1;
        }
      }
      //Impar, instala no SW
      else
      {
        if (group == 1)
        {
          packetoutport = ul2swPort;
        }
        else
        {
          packetoutport = dl2swPort;
        }
        InstallUDPTrafficRules(switchDeviceSw, newId, false, group);
        m_accepted += 1;
      }
    }
    //Packet out para o switch se o trafego foi aceito
    if (!drop)
    {
      struct ofl_msg_packet_out reply;
      reply.header.type = OFPT_PACKET_OUT;
      reply.buffer_id = msg->buffer_id;
      reply.in_port = inPort;
      reply.data_length = 0;
      reply.data = 0;
      if (msg->buffer_id == NO_BUFFER)
      {
        // No packet buffer. Send data back to switch
        reply.data_length = msg->data_length;
        reply.data = msg->data;
      }

      //Output
      struct ofl_action_output *a =
          (struct ofl_action_output*)xmalloc (sizeof (struct ofl_action_output));
      a->header.type = OFPAT_OUTPUT;
      a->port = packetoutport; //Porta do switch UL para switch escolhido
      a->max_len = 0;
      reply.actions_num = 1;
      reply.actions = (struct ofl_action_header**)&a;
      SendToSwitch (swtch, (struct ofl_msg_header*)&reply, xid);
      free (a);
    }
  }
  else
  {
    NS_LOG_WARN ("This controller can't handle the packet. Unknown reason.");
  }
  // All handlers must free the message when everything is ok
  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

void
CustomController::HandshakeSuccessful (Ptr<const RemoteSwitch> swtch)
{
  NS_LOG_FUNCTION (this << swtch);
  //OFSwitch13Controller::HandshakeSuccessful(swtch);
  /*--------LEARNING CONTROLLER--------*/

  // Get the switch datapath ID
  uint64_t swDpId = swtch->GetDpId ();

  // After a successfull handshake, let's install the table-miss entry, setting
  // to 128 bytes the maximum amount of data from a packet that should be sent
  // to the controller.
  DpctlExecute (swDpId, "flow-mod cmd=add,table=0,prio=0 "
                "apply:output=ctrl:128");

  // Configure te switch to buffer packets and send only the first 128 bytes of
  // each packet sent to the controller when not using an output action to the
  // OFPP_CONTROLLER logical port.
  DpctlExecute (swDpId, "set-config miss=128");

  // Create an empty L2SwitchingTable and insert it into m_learnedInfo
  L2Table_t l2Table;
  std::pair<uint64_t, L2Table_t> entry (swDpId, l2Table);
  auto ret = m_learnedInfo.insert (entry);
  if (ret.second == false)
  {
    NS_LOG_ERROR ("Table exists for this datapath.");
  }
}

void
CustomController::InstallDropRule (Ptr<OFSwitch13Device> switchDevice,
                                       uint32_t trafficId)
{
  NS_LOG_FUNCTION (this << switchDevice << trafficId);

  //Recuperando informacoes do trafego pelo ID
  struct trafficInfo &info = m_trafficInfo[trafficId];
  Ipv4Address srcip = info.srcip;
  Ipv4Address dstip = info.dstip;
  uint16_t srcport = info.srcport;
  uint16_t dstport = info.dstport;

  //Instala a regra de drop para o tráfego no switch passado por parametro
  std::ostringstream cmd;
  cmd << "flow-mod cmd=add,prio=128,idle=15,table=0,cookie=" << GetUint32Hex (trafficId)
        << " eth_type=0x800,ip_src=" << srcip << ",ip_dst=" << dstip << ",ip_proto=17,udp_src=" << srcport << ",udp_dst=" << dstport;
  DpctlExecute (switchDevice->GetDatapathId (), cmd.str ());
  
}

void
CustomController::InstallUDPTrafficRules (Ptr<OFSwitch13Device> switchDevice,
                                          uint32_t trafficId, 
                                          bool modify, uint32_t group)
{
  NS_LOG_FUNCTION (this << switchDevice << trafficId << modify << group);
  /*
  Portas
    UL->HW: 1
    UL->SW: 2
    DL->HW: 1
    DL->SW: 2
    SW->DL: 2
    SW->UL: 1
    HW->DL: 2
    HW->UL: 1
  DPID
    1=ul / 2=dl / 3=hw / 4=sw
  */

  //Recuperando informacoes do trafego pelo ID
  struct trafficInfo &info = m_trafficInfo[trafficId];
  Ipv4Address srcip = info.srcip;
  Ipv4Address dstip = info.dstip;
  uint16_t srcport = info.srcport;
  uint16_t dstport = info.dstport;

  //Instalando regras no switch HW/SW
  // Instalar as regras identificando o trafego pela porta no cookie para facilitar na remoção/alteração.
  std::ostringstream cmd;
  cmd << "flow-mod cmd=add,prio=128,idle=15,flags="<<OFPFF_SEND_FLOW_REM<<",table=0,cookie=" << GetUint32Hex (trafficId)
      << " eth_type=0x800,ip_src=" << srcip << ",ip_dst=" << dstip << ",ip_proto=17,udp_src=" << srcport << ",udp_dst=" << dstport;
  if (group == 1)
  {
    cmd << " write:group=1";
    DpctlExecute (switchDevice->GetDatapathId (), cmd.str ());
  }
  else
  {
    NS_ASSERT_MSG(group == 2, "Grupo não identificado!");
    cmd << " write:group=2";
    DpctlExecute (switchDevice->GetDatapathId (), cmd.str ());
  }
  
  //Instalando as regras no switch UL/DL, caso seja uma nova regra (não uma modificação de uma já existente)
  if(!modify)
  {
    if(switchDevice->GetDatapathId() == m_dpidHW)
    {
      //Regra UL->HW
      if (group == 1)
      {
        std::ostringstream cmdUl;
        cmdUl << "flow-mod cmd=add,prio=128,idle=15,table=0,cookie=" << GetUint32Hex (trafficId)
            << " eth_type=0x800,ip_src=" << srcip << ",ip_dst=" << dstip << ",ip_proto=17,udp_src=" << srcport  << ",udp_dst=" << dstport 
            << " apply:output=" << ul2hwPort;
        DpctlExecute (switchDeviceUl->GetDatapathId (), cmdUl.str ());
      }
      else
      {
        //Regra DL->HW
        std::ostringstream cmdDl;
        cmdDl << "flow-mod cmd=add,prio=128,idle=15,table=0,cookie=" << GetUint32Hex (trafficId)
            << " eth_type=0x800,ip_src=" << srcip << ",ip_dst=" << dstip << ",ip_proto=17,udp_dst=" << dstport<< ",udp_src=" << srcport 
            << " apply:output=" << dl2hwPort;
        DpctlExecute (switchDeviceDl->GetDatapathId (), cmdDl.str ());
      }
    }
    else
    {
      NS_ASSERT_MSG(switchDevice->GetDatapathId() == m_dpidSW, "Switch deveria ser o SW!");
      //Regra UL->SW
      if (group == 1)
      {
        std::ostringstream cmdUl;
        cmdUl << "flow-mod cmd=add,prio=128,idle=15,table=0,cookie=" << GetUint32Hex (trafficId)
            << " eth_type=0x800,ip_src=" << srcip << ",ip_dst=" << dstip << ",ip_proto=17,udp_src=" << srcport  << ",udp_dst=" << dstport 
            << " apply:output=" << ul2swPort;
        DpctlExecute (switchDeviceUl->GetDatapathId (), cmdUl.str ());
      }
      else
      {
        //Regra DL->SW
        std::ostringstream cmdDl;
        cmdDl << "flow-mod cmd=add,prio=128,idle=15,table=0,cookie=" << GetUint32Hex (trafficId)
            << " eth_type=0x800,ip_src=" << srcip << ",ip_dst=" << dstip << ",ip_proto=17,udp_dst=" << dstport << ",udp_src=" << srcport 
            << " apply:output=" << dl2swPort;
        DpctlExecute (switchDeviceDl->GetDatapathId (), cmdDl.str ());
      }
    }
  }
}

void
CustomController::RemoveTrafficRules (Ptr<OFSwitch13Device> switchDevice,
                                      uint32_t teid)
{
  NS_LOG_FUNCTION (this << switchDevice << teid);

  // Usar o teid como identificador da regra pelo campo cookie.
  std::ostringstream cmd;
  cmd << "flow-mod cmd=del,cookie=" << GetUint32Hex (teid)
      << ",cookie_mask=0xFFFFFFFFFFFFFFFF";

  DpctlExecute (switchDevice->GetDatapathId (), cmd.str ());
}

void
CustomController::MoveTrafficRules (Ptr<OFSwitch13Device> srcSwitchDevice,
                                    Ptr<OFSwitch13Device> dstSwitchDevice,
                                    uint32_t trafficId)
{
  NS_LOG_FUNCTION (this << srcSwitchDevice << dstSwitchDevice << trafficId);

  // Instalando a nova regra no switch de destino.
  Simulator::Schedule (MilliSeconds (500), &CustomController::InstallUDPTrafficRules,
                       this, dstSwitchDevice, trafficId, true, 1); //Grupo 1 pois somente regras de Ulink sao movidas*/
  // Atualizando a regra nos switches UL e DL
  Simulator::Schedule (MilliSeconds (1500), &CustomController::UpdateDlUlRules,
                       this, trafficId); //Cookie é o identificador do tráfego
  // Removendo a regra no switch de origem
  Simulator::Schedule (Seconds (2), &CustomController::RemoveTrafficRules,
                       this, srcSwitchDevice, trafficId);
}

void
CustomController::UpdateDlUlRules (uint32_t cookie)
{
  NS_LOG_FUNCTION (this << cookie);
  // Modificar as regras com o cookie
  std::ostringstream cmdUl, cmdDl;
  cmdUl << "flow-mod cmd=mod,table=0,cookie=" << GetUint32Hex (cookie) << ",cookie_mask=0xFFFFFFFFFFFFFFFF";
  cmdDl << "flow-mod cmd=mod,table=0,cookie=" << GetUint32Hex (cookie) << ",cookie_mask=0xFFFFFFFFFFFFFFFF";
  cmdUl << " apply:output=" << ul2hwPort;
  cmdDl << " apply:output=" << dl2hwPort;
  DpctlExecute (switchDeviceUl->GetDatapathId (), cmdUl.str ());
  DpctlExecute (switchDeviceDl->GetDatapathId (), cmdDl.str ());
}

ofl_err 
CustomController::HandleFlowRemoved (struct ofl_msg_flow_removed *msg, Ptr<const RemoteSwitch> swtch,
                                     uint32_t xid)
{
  NS_LOG_FUNCTION (this << msg << swtch << xid);
  NS_LOG_DEBUG("Regra expirada ou removida");
  if(m_qosRoute)
  {
    return 0;
  }
  else if(swtch->GetDpId() == m_dpidHW)
  {
    m_regrasHw -= 1;
  }
  return 0;
}

void
CustomController::ControllerTimeout ()
{
  NS_LOG_FUNCTION (this);
  // Escalona a próxima operação de timeout para o controlador.
  Simulator::Schedule (m_estTimeout, &CustomController::ControllerTimeout, this);
  // Para a política estática vamos apenas atualizar a variavel com o numero de regras no switch HW.
  m_regrasHw = switchDeviceHw->GetFlowTableEntries(0);
}

// Declarando tipo de par cookie / vazão.
typedef std::pair<uint32_t, DataRate> CookieThp_t;

// Declarando tipo de função que recever dois pares CookieThp_t e retorna bool.
typedef std::function<bool (CookieThp_t, CookieThp_t)> CookieThpComp_t;

// Comparador para ordenar o mapa de vazão por tráfego.
CookieThpComp_t thpComp = [] (CookieThp_t elem1, CookieThp_t elem2)
{
  return elem1.second > elem2.second;
};

void
CustomController::QoSControllerTimeout ()
{
  NS_LOG_FUNCTION (this);

  // Escalona a próxima operação de timeout para o controlador.
  Simulator::Schedule (m_qosTimeout, &CustomController::QoSControllerTimeout, this);

  // Para a política dinâmica, vamos percorrer a tabela do switch SW e montar uma
  // lista ordenada dos tráfegos com vazão decrescente para que possamos mover
  // os tráfegos de maior vazão para o switch de HW sem extrapolar sua
  // capacidade máxima.
  struct datapath *datapath = switchDeviceSw->GetDatapathStruct ();
  struct flow_table *table = datapath->pipeline->tables[0];
  struct flow_entry *entry;

  std::map<uint32_t, DataRate> thpByTeid;
  double bytes = 0;

  // Percorrendo tabela e recuperando informações sobre os tráfegos.
  LIST_FOR_EACH (entry, struct flow_entry, match_node, &table->match_entries)
  {
    if(GetUint32Hex(entry->stats->cookie) == GetUint32Hex (500))
    {
      continue; //Ignora regra de ping
    }
    struct ofl_flow_stats *stats = entry->stats;
    Time active = Simulator::Now () - MilliSeconds (entry->created);

    bytes = stats->byte_count;

    // Calculando a vazão total para o tráfego.
    DataRate throughput (bytes * 8 / active.GetSeconds ());
    thpByTeid [entry->stats->cookie] = throughput;
    NS_LOG_DEBUG ("Traffic " << entry->stats->cookie <<
                  " with throughput " << throughput);
  }

  // Construindo um set com as vazões ordenadas em descrescente.
  std::set<CookieThp_t, CookieThpComp_t> thpSorted (
    thpByTeid.begin (), thpByTeid.end (), thpComp);

  // Verificando os recursos disponíveis no switch de HW:
  uint32_t tabHwFree =
    switchDeviceHw->GetFlowTableSize (0) * m_blockThs -
    switchDeviceHw->GetFlowTableEntries (0);
  NS_LOG_DEBUG ("Resources on HW switch: " << tabHwFree <<
                " table entries");

  // Percore a lista de tráfego movendo os primeiros para o switch de HW.
  for (auto element : thpSorted)
  {
      if (tabHwFree < 1)
      {
        // Parar se não houver mais recursos disponíveis no HW.
        break;
      }
      // Move o tráfego do switch de SW para o switch de HW.
      uint16_t cookie = element.first;
      if (cookie != 0){
        NS_LOG_DEBUG ("Moving traffic ID " << cookie << " to HW switch.");
        MoveTrafficRules (switchDeviceSw, switchDeviceHw, cookie);
        tabHwFree -= 1;
      }
  }
}

} // namespace ns3
