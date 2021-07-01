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

#include "qos-custom-controller.h"
#include "applications/svelte-client.h"
#include <algorithm>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <ns3/ofswitch13-module.h>
#include <set>

using namespace std;

/*
  TODO
  - Programar uma politica que possa voltar tráfegos do HW para o SW caso o SW tenha tráfegos maiores que os menores do HW
    Ordenar todos os tráfegos ativos por vazão, pegar os N maiores e colocar no HW, onde N é o tamanho o HW. 
    Se já estiver no HW, deixa lá. Se não, move para o HW.
    Quem estava no HW e não está na lista, volta para o SW.
*/

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QosCustomController");
NS_OBJECT_ENSURE_REGISTERED (QosCustomController);

QosCustomController::QosCustomController ()
{
  NS_LOG_FUNCTION (this);
  m_blocked = 0;
  m_accepted = 0;
  m_regrasAtivas = 0;
}

QosCustomController::~QosCustomController ()
{
  NS_LOG_FUNCTION (this);
}

TypeId
QosCustomController::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QosCustomController")
    .SetParent<OFSwitch13Controller> ()
    .AddConstructor<QosCustomController> ()
    .AddAttribute ("BlockThs",
                   "Switch overloaded block threshold.",
                   DoubleValue (1.0),
                   MakeDoubleAccessor (&QosCustomController::m_blockThs),
                   MakeDoubleChecker<double> (0.8, 1.0))
    .AddAttribute ("BlockPolicy",
                   "Switch overloaded block policy (true for block).",
                   BooleanValue (true),
                   MakeBooleanAccessor (&QosCustomController::m_blockPol),
                   MakeBooleanChecker ())
    .AddAttribute ("SmartRouting",
                   "True for QoS routing, false for IP routing.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&QosCustomController::m_qosRoute),
                   MakeBooleanChecker ())
    .AddAttribute ("StatsTimeout",
                   "Stats timeout interval in QoS mode.",
                   TimeValue (Seconds (10)),
                   MakeTimeAccessor (&QosCustomController::m_statsTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("MoveTimeout",
                   "Time to move rules from SW switch to HW switch.",
                   TimeValue (Seconds (10)),
                   MakeTimeAccessor (&QosCustomController::m_moveTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("LoadTimeout",
                   "Controller load timeout interval.",
                   TimeValue (Seconds (15)),
                   MakeTimeAccessor (&QosCustomController::m_loadTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("NewSwDelay",
                   "Time to start a new SW switch.",
                   TimeValue (Seconds (10)),
                   MakeTimeAccessor (&QosCustomController::m_newSwDelay),
                   MakeTimeChecker ())
    .AddAttribute ("MinSwLoad",
                   "Minimum load threshold for software switches.",
                   DoubleValue (0.8),
                   MakeDoubleAccessor (&QosCustomController::m_minSwLoad),
                   MakeDoubleChecker<double> (0.5, 0.8))
    .AddAttribute ("MaxSwLoad",
                   "Maximum load threshold for software switches.",
                   DoubleValue (0.95),
                   MakeDoubleAccessor (&QosCustomController::m_maxSwLoad),
                   MakeDoubleChecker<double> (0.8, 1.0))    
    .AddAttribute ("ActiveSW",
                   "Number of software switches actives.",
                   UintegerValue (1),
                   MakeUintegerAccessor (&QosCustomController::m_activeSW),
                   MakeUintegerChecker<uint32_t> ())

    .AddTraceSource ("Request", "The request trace source.",
                     MakeTraceSourceAccessor (&QosCustomController::m_requestTrace),
                     "ns3::QosCustomController::RequestTracedCallback")
    .AddTraceSource ("Release", "The release trace source.",
                     MakeTraceSourceAccessor (&QosCustomController::m_releaseTrace),
                     "ns3::QosCustomController::ReleaseTracedCallback")
  ;
  return tid;
}

void
QosCustomController::NotifyHwSwitch (Ptr<OFSwitch13Device> switchDevice,
                                  uint32_t ulPort, uint32_t dlPort)
{
  NS_LOG_FUNCTION (this << switchDevice << ulPort << dlPort);

  // Salvando switch e número de portas.
  switchDeviceHw = switchDevice;

  // Neste switch estamos configurando dois grupos:
  // Grupo 1, usado para enviar pacotes na direção de uplink.
  // Grupo 2, usado para enviar pacotes na direção de downlink.
  std::ostringstream cmd1, cmd2;
  cmd1 << "group-mod cmd=add,type=ind,group=1"
       << " weight=0,port=any,group=any"
       << " output=" << dlPort;

  cmd2 << "group-mod cmd=add,type=ind,group=2"
       << " weight=0,port=any,group=any"
       << " output=" << ulPort;

  DpctlExecute (switchDeviceHw->GetDatapathId (), cmd1.str ());
  DpctlExecute (switchDeviceHw->GetDatapathId (), cmd2.str ());
}

void
QosCustomController::NotifySwSwitch (Ptr<OFSwitch13Device> switchDevice,
                                  uint32_t ulPort, uint32_t dlPort)
{
  NS_LOG_FUNCTION (this << switchDevice << ulPort << dlPort);

  // Salvando switch e número de portas.
  switchDevicesSw.Add(switchDevice);

  // Neste switch estamos configurando dois grupos:
  // Grupo 1, usado para enviar pacotes na direção de uplink.
  // Grupo 2, usado para enviar pacotes na direção de downlink.
  std::ostringstream cmd1, cmd2;
  cmd1 << "group-mod cmd=add,type=ind,group=1"
       << " weight=0,port=any,group=any"
       << " output=" << dlPort;

  cmd2 << "group-mod cmd=add,type=ind,group=2"
       << " weight=0,port=any,group=any"
       << " output=" << ulPort;

  DpctlExecute (switchDevice->GetDatapathId (), cmd1.str ());
  DpctlExecute (switchDevice->GetDatapathId (), cmd2.str ());
}

void
QosCustomController::NotifyUlSwitch (Ptr<OFSwitch13Device> switchDevice,
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
QosCustomController::NotifyDlSwitch (Ptr<OFSwitch13Device> switchDevice,
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
QosCustomController::NotifyDl2Sv (uint32_t portNo, Ipv4Address ipAddr)
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
QosCustomController::NotifyUl2Sv (uint32_t portNo, Ipv4Address ipAddr)
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
QosCustomController::NotifyDl2Cl (uint32_t portNo, Ipv4Address ipAddr)
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
QosCustomController::NotifyUl2Cl (uint32_t portNo, Ipv4Address ipAddr)
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
QosCustomController::NotifyTopologyBuilt ()
{
  NS_LOG_FUNCTION (this);

  //Instala a regra de ping no switch HW
  std::ostringstream cmdUlink , cmdDlink;
  cmdUlink << "flow-mod cmd=add,prio=128,table=0,cookie=" << GetUint64Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_src=" << 65534 << ",udp_dst=" << 7000;
  cmdDlink << "flow-mod cmd=add,prio=128,table=0,cookie=" << GetUint64Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_dst=" << 65534 << ",udp_src=" << 7000;
  // Saidas de Uplink/Downlink.
  cmdUlink << " write:group=1";
  cmdDlink << " write:group=2";
  DpctlExecute (switchDeviceHw->GetDatapathId (), cmdUlink.str ());
  DpctlExecute (switchDeviceHw->GetDatapathId (), cmdDlink.str ());

  //Instala a regra de ping no switch SW
  std::ostringstream cmdUlinkSW , cmdDlinkSW;
  cmdUlinkSW << "flow-mod cmd=add,prio=228,table=0,cookie=" << GetUint64Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_src=" << 65535 << ",udp_dst=" << 7001;
  cmdDlinkSW << "flow-mod cmd=add,prio=228,table=0,cookie=" << GetUint64Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_dst=" << 65535 << ",udp_src=" << 7001;
  // Saidas de Uplink/Downlink.
  cmdUlinkSW << " write:group=1";
  cmdDlinkSW << " write:group=2";
  for (size_t i = 0; i<m_maxSW; i++){
    DpctlExecute (switchDevicesSw.Get(i)->GetDatapathId (), cmdUlinkSW.str ());
    DpctlExecute (switchDevicesSw.Get(i)->GetDatapathId (), cmdDlinkSW.str ());
  }

  // Instala a regra de ping nos switches UL e DL
  //HW
  std::ostringstream cmdUL , cmdDL;
  cmdUL << "flow-mod cmd=add,prio=128,table=0,cookie=" << GetUint64Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_src=" << 65534 << ",udp_dst=" << 7000;
  cmdDL << "flow-mod cmd=add,prio=128,table=0,cookie=" << GetUint64Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_dst=" << 65534 << ",udp_src=" << 7000;
  // Saidas de Uplink/Downlink.
  cmdUL << " apply:output="<< ul2hwPort;
  cmdDL << " apply:output=" << dl2hwPort;
  DpctlExecute (switchDeviceUl->GetDatapathId (), cmdUL.str ());
  DpctlExecute (switchDeviceDl->GetDatapathId (), cmdDL.str ());

  //SW
  std::ostringstream cmdULSW , cmdDLSW;
  cmdULSW << "flow-mod cmd=add,prio=228,table=0,cookie=" << GetUint64Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_src=" << 65535 << ",udp_dst=" << 7001;
  cmdDLSW << "flow-mod cmd=add,prio=228,table=0,cookie=" << GetUint64Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_dst=" << 65535 << ",udp_src=" << 7001;
  // Saidas de Uplink/Downlink.
  cmdULSW << " write:group="<<m_activeSW;
  cmdDLSW << " write:group="<<m_activeSW;
  DpctlExecute (switchDeviceUl->GetDatapathId (), cmdULSW.str ());
  DpctlExecute (switchDeviceDl->GetDatapathId (), cmdDLSW.str ());
}

void
QosCustomController::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  switchDeviceUl = 0;
  switchDeviceDl = 0;
  switchDeviceHw = 0;
  m_saida = 0;
  m_printTraffic = 0;
  m_move = 0;
  m_teidAddr.clear ();
  OFSwitch13Controller::DoDispose ();
}

void
QosCustomController::NotifyConstructionCompleted (void)
{
  NS_LOG_FUNCTION (this);
  // Numero maximo de switches SW
  UintegerValue max_SW;
  GlobalValue::GetValueByName ("MaxSW", max_SW);
  m_maxSW = max_SW.Get ();
  StringValue stringValue;
  GlobalValue::GetValueByName ("OutputPrefix", stringValue);
  std::string prefix = stringValue.Get ();
  m_saida = Create<OutputStreamWrapper> (prefix+"statistics.log", std::ios::out); 
  // Print the header in output file.
  *m_saida->GetStream ()
    << boolalpha << right << fixed << setprecision (3)
    << setw (8)  << "TimeSec"
    << " " << setw (8)  << "RegrasAceitas"
    << " " << setw (8)  << "RegrasBloqueadas"
    << " " << setw (8)  << "SWAtivos"
    << " " << setw (8)  << "AvgLoad"
    << std::endl;

  m_log = Create<OutputStreamWrapper> (prefix+"logDecisaoSwitchesSW.log", std::ios::out); 
  // Print the header in output file.
  *m_log->GetStream ()
    << boolalpha << right << fixed << setprecision (3)
    << setw (8)  << "TimeSec"
    << " " << setw (8)  << "SwAtivosAntes"
    << " " << setw (8)  << "AvgCPULoad"
    << " " << setw (8)  << "Decisão"
    << " " << setw (8)  << "SwAtivosDepois"
    << std::endl;

  m_move = Create<OutputStreamWrapper> (prefix+"RegrasMovidas.log", std::ios::out); 
  // Print the header in output file.
  *m_move->GetStream ()
    << boolalpha << right << fixed << setprecision (3)
    << setw (8)  << "TimeSec"
    << " " << setw (8)  << "SRC"
    << " " << setw (8)  << "DST"
    << " " << setw (8) << "Cookie" 
    << " " << setw (23)  << " SRCIP"  
    << " " << setw (14)  << " DSTIP"  
    << " " << setw (13)  << " SRCPort"  
    << " " << setw (8)  << " DSTPort"  
    << " " << setw (8)  << " Protocol"  
    << " " << setw (8)  << " NumSwitches"  
    << " " << setw (6)  << "Active"  
    << " " << setw (9)  << " InCache" 
    << " " << setw (8)  << " Blocked"  
    << " " << setw (8)  << " Direction"  
    //<< " " << setw (8)  << " Cmd"  
    << " " << setw (8)  << " TimeCreated"  
    << " " << setw (9)  << " TimeFinished"  
    //<< " " << setw (8)  << " Bytes" 
    << " " << setw (13)  << " ExpBytes"  
    << " " << setw (10)  << " Rate"
    << std::endl;

  m_printTraffic = Create<OutputStreamWrapper> (prefix+"saidaStruct.log", std::ios::out); 
  // Print the header in output file.
  *m_printTraffic->GetStream ()
    << setw (8) << "Cookie" 
    << " " << setw (21)  << " SRCIP"  
    << " " << setw (14)  << " DSTIP"  
    << " " << setw (13)  << " SRCPort"  
    << " " << setw (8)  << " DSTPort"  
    << " " << setw (8)  << " Protocol"  
    << " " << setw (8)  << " NumSwitches"  
    << " " << setw (6)  << "Active"  
    << " " << setw (9)  << " InCache" 
    << " " << setw (8)  << " Blocked"  
    << " " << setw (8)  << " Direction"  
    //<< " " << setw (8)  << " Cmd"  
    << " " << setw (8)  << " TimeCreated"  
    << " " << setw (9)  << " TimeFinished"  
    //<< " " << setw (8)  << " Bytes" 
    << " " << setw (13)  << " ExpBytes"  
    << " " << setw (14)  << " Rate"
    << std::endl;

  // Escalona a primeira operação de timeout para o controlador.
  Simulator::Schedule (m_statsTimeout, &QosCustomController::StatsTimeout, this);
  Simulator::Schedule (Seconds(1), &QosCustomController::imprimeSaida, this);
  if(m_moveTimeout > Seconds(0))
  {
    Simulator::Schedule (m_moveTimeout, &QosCustomController::MoveTimeout, this);
  }
  if(m_loadTimeout > Seconds(0))
  {
    Simulator::Schedule (m_loadTimeout, &QosCustomController::LoadControllerTimeout, this);
  }
  else
  {
    Simulator::Schedule (m_loadTimeout, &QosCustomController::PrintLoadTimeout, this);
  }
  OFSwitch13Controller::NotifyConstructionCompleted ();
}

void
QosCustomController::imprimeSaida(){
  double load = 0;
  double totalusage = 0;
  for (size_t i = 0; i<m_activeSW; i++)
  {
    totalusage += switchDevicesSw.Get(i)->GetCpuUsage();
  }
  load = totalusage/m_activeSW;

  *m_saida->GetStream ()
    << setw (8) << Simulator::Now().GetSeconds()
    << " " << setw (8) << m_accepted
    << " " << setw (12) << m_blocked
    << " " << setw (14) << m_activeSW
    << " " << setw (10) << load
    << std::endl;
    m_accepted = 0;
    m_blocked = 0;
  Simulator::Schedule (Seconds(1), &QosCustomController::imprimeSaida, this);
}

void
QosCustomController::PrintTrafficInfo(){
  
  NS_LOG_FUNCTION (this);
  for(auto &info : m_trafficInfo)
  {
    *m_printTraffic->GetStream ()
    << setw (8) << GetUint64Hex(info.second.cookie)
    << " " << setw (8) << info.second.srcip
    << " " << setw (8) << info.second.dstip
    << " " << setw (8) << info.second.srcport
    << " " << setw (8) << info.second.dstport
    << " " << setw (5) << info.second.protocol
    << " " << setw (8) << info.second.numSwitches
    << " " << setw (11) << info.second.active
    << " " << setw (8) << info.second.inCache
    << " " << setw (8) << info.second.blocked
    << " " << setw (8) << info.second.direction
    //<< " " << setw (8) << info.second.cmd
    << " " << setw (16) << info.second.timeCreated.GetSeconds()
    << " " << setw (17) << info.second.timeFinished.GetSeconds()
    //<< " " << setw (8) << info.second.bytes
    << " " << setw (13) << info.second.expBytes
    << " " << setw (14) << info.second.rate.GetBitRate()
    << std::endl;
  }
}

Ipv4Address
QosCustomController::ExtractIpv4Address (uint32_t oxm_of, struct ofl_match* match)
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

bool
QosCustomController::CheckHwBlock()
{
  /*
  Retorna true se o switch HW está bloqueado. 
  False se ainda tem espaço para novas regras e load menor que o limite.
  */
  if(switchDeviceHw->GetCpuUsage() >= m_maxSwLoad || switchDeviceHw->GetFlowTableUsage(0) >= m_maxSwLoad)
  {
    return true;
  }
  else
  {
    return false;
  }
}

bool
QosCustomController::CheckSwBlock()
{
  /*
  Retorna true se os switches SW estão bloqueados. 
  False se load menor que o limite.
  */
  double totalusage = 0;
  double load = 0;
  for (size_t i = 0; i<m_activeSW; i++)
  {
    totalusage += switchDevicesSw.Get(i)->GetCpuUsage();
  }
  load = totalusage/m_activeSW;
  if(load >= m_maxSwLoad)
  {
    return true;
  }
  else
  {
    return false;
  }  
}

bool
QosCustomController::CheckBlockStatus()
{
  /*
    Verifica as condições de bloqueio em 4 cenários diferentes:
    Retorna true se switches estão bloqueados. False se não.
    
    1- Quando movetimeout e loadtimeout for 0 (nao pode mover ou aumentar switches SW), bloquear quando a média de load 
    dos switches SW ativos for maior que o limite de bloqueio

    2- Quando movetimeout=0 e loadtimeout>0 (só pode aumentar/diminuir SW), bloquear quando a média de load dos switches
    SW ativos for maior que o limite de bloqueio E quando estiver no máximo de SW (activeSW = maxSW)

    3- Quando movetimeout>0 e loadtimeout=0 (só pode mover), bloquear quando a média de load dos switches SW ativos for
    maior que o limite de bloqueio E o switch de hardware estiver sobrecarregado (regras ou load)

    4- Quando movetimeout>0 e loadtimeout>0 (pode mover e aumentar/diminuir SW), bloquear quando a média de load dos switches SW ativos for
    maior que o limite de bloqueio E o switch de hardware estiver sobrecarregado (regras ou load) E quando estiver no máximo de SW (activeSW = maxSW)
  */

  //Cenario 1
  if(m_moveTimeout == Seconds(0) && m_loadTimeout == Seconds(0))
  {
    if(CheckSwBlock())
    {
      return true;
    }
    else
    {
      return false;
    }
  }
  //Cenario 2
  else if(m_moveTimeout == Seconds(0) && m_loadTimeout > Seconds(0))
  {
    if(CheckSwBlock() && m_activeSW >= m_maxSW)
    {
      return true;
    }
    else
    {
      return false;
    }
  }
  //Cenario 3
  else if(m_moveTimeout > Seconds(0) && m_loadTimeout == Seconds(0))
  {
    if(CheckSwBlock() && CheckHwBlock())
    {
      return true;
    }
    else
    {
      return false;
    }
  }
  //Cenario 4
  else
  {
    if(CheckSwBlock() && CheckHwBlock() && m_activeSW >= m_maxSW)
    {
      return true;
    }
    else
    {
      return false;
    }
  }
}

ofl_err
QosCustomController::HandlePacketIn (
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
    //Porta fisica
    size_t len = 0;
    struct ofl_match_tlv *input = NULL;
    //InPort é o mesmo número do grupo (1 = uplink, 2 = downlink)
    uint32_t inPort;
    len = OXM_LENGTH (OXM_OF_IN_PORT);
    input = oxm_match_lookup (OXM_OF_IN_PORT, (struct ofl_match*)msg->match);
    memcpy (&inPort, input->value, len);

    //UDP SRC
    uint16_t udp_src;
    len = OXM_LENGTH (OXM_OF_UDP_SRC);
    input = oxm_match_lookup (OXM_OF_UDP_SRC, (struct ofl_match*)msg->match);
    memcpy (&udp_src, input->value, len);

    //UDP DST
    uint16_t udp_dst;
    len = OXM_LENGTH (OXM_OF_UDP_DST);
    input = oxm_match_lookup (OXM_OF_UDP_DST, (struct ofl_match*)msg->match);
    memcpy (&udp_dst, input->value, len);

    //IP src/dst
    Ipv4Address srcIp, dstIp;
    srcIp = ExtractIpv4Address (OXM_OF_IPV4_SRC, (struct ofl_match*)msg->match);
    dstIp = ExtractIpv4Address (OXM_OF_IPV4_DST, (struct ofl_match*)msg->match);

    //Antes de criar a struct, vamos procurar se esse trafego já existe
    bool newtraffic = true;
    uint64_t newcookie = CookieCreate(srcIp, dstIp, udp_src, udp_dst, IP_TYPE_UDP);
    if(m_trafficInfo.count(newcookie) != 0)
    {
      if(m_trafficInfo[newcookie].blocked){
        NS_LOG_ERROR ("Packet in de trafego bloqueado: " << GetUint64Hex(newcookie));
        return 0;
      }
      //Trafego já existe, instalar apenas no switch que deu o packet in e aumentar o numswitches desse trafego
      struct trafficInfo &tinfo = m_trafficInfo[newcookie];
      if(!tinfo.active)
      {
        std::cout << "Packet in de tráfego inativo! Cookie: " << GetUint64Hex(newcookie) << std::endl;
        return 0;
      }
      newtraffic = false;
      tinfo.numSwitches++;
      DpctlExecute(swtch->GetDpId(), tinfo.cmd);
    }
  
    //Politicas
    bool drop = false;
    if(m_qosRoute)
    {
      //Caso seja um novo tráfego, instala em todos os switches SW
      if(newtraffic)
      {
        //Cria struct com as informações
        struct trafficInfo info;
        info.cookie = newcookie;
        info.srcip = srcIp;
        info.dstip = dstIp;
        info.srcport = udp_src;
        info.dstport = udp_dst;
        info.protocol = IP_TYPE_UDP;
        info.active = true;
        info.bytes = 0;
        info.timeCreated = Simulator::Now();
        info.rate = 0;
        info.expBytes = 0;
        info.inCache = false;
        info.direction = inPort;
        info.blocked = false;
        //Mapa
        std::pair<uint64_t, struct trafficInfo> entry (newcookie, info);
        m_trafficInfo.insert(entry);
        NS_LOG_DEBUG("New traffic ID: " << newcookie);
        //Verificando se o SW tem regras disponiveis para instalar
        double maxtableusage = 0;
        for (size_t i = 0; i<m_activeSW; i++)
        {
          if(maxtableusage < switchDevicesSw.Get(i)->GetFlowTableUsage(0))
          {
            maxtableusage = switchDevicesSw.Get(i)->GetFlowTableUsage(0);
          }
        }
        //Instala em todos os switches SW se os switches não estão bloqueados
        if(maxtableusage < 0.95 && !CheckBlockStatus()){
          m_trafficInfo[newcookie].numSwitches = m_activeSW;
          for (size_t i = 0; i<m_activeSW; i++){
            InstallUDPTrafficRules(switchDevicesSw.Get(i), newcookie, inPort);
          }
          m_accepted += 1;
          m_regrasAtivas += 1;
        }
        else
        {
          m_blocked += 1; 
          m_trafficInfo[newcookie].numSwitches = 0;
          m_trafficInfo[newcookie].blocked = true; 
          m_trafficInfo[newcookie].active = false; 
          InstallDropRule(newcookie);
          drop = true;
          std::cout << "Regra com cookie " << newcookie << " bloqueada" << std::endl; 
        }
       
      }
    }
    else
    {
      NS_LOG_ERROR("Politica nao identificada");
    }
    if(!drop)
    {
      //Packet out para o switch se o trafego foi aceito    
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
      struct ofl_action_group *a =
        (struct ofl_action_group*)xmalloc (sizeof (struct ofl_action_group));
      a->header.type = OFPAT_OUTPUT;
      a->group_id = inPort; //Grupo
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
QosCustomController::HandshakeSuccessful (Ptr<const RemoteSwitch> swtch)
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
QosCustomController::InstallDropRule (uint64_t trafficId)
{
  NS_LOG_FUNCTION (this << trafficId);

  //Recuperando informacoes do trafego pelo ID
  struct trafficInfo &info = m_trafficInfo[trafficId];
  Ipv4Address srcip = info.srcip;
  Ipv4Address dstip = info.dstip;
  uint16_t srcport = info.srcport;
  uint16_t dstport = info.dstport;

  //Instala a regra de drop para o tráfego no switch passado por parametro
  std::ostringstream cmdUL, cmdDL;
  cmdUL << "flow-mod cmd=add,prio=500,idle=30,table=0,cookie=" << GetUint64Hex (trafficId)
        << " eth_type=0x800,ip_src=" << srcip << ",ip_dst=" << dstip << ",ip_proto=17,udp_src=" << srcport << ",udp_dst=" << dstport;

  cmdDL << "flow-mod cmd=add,prio=500,idle=30,table=0,cookie=" << GetUint64Hex (trafficId)
        << " eth_type=0x800,ip_src=" << dstip << ",ip_dst=" << srcip << ",ip_proto=17,udp_src=" << dstport << ",udp_dst=" << srcport;

  if(info.direction == 1)
  {
    DpctlExecute (switchDeviceUl->GetDatapathId (), cmdUL.str ());
    DpctlExecute (switchDeviceDl->GetDatapathId (), cmdDL.str ());
  }
  else
  {
    DpctlExecute (switchDeviceUl->GetDatapathId (), cmdDL.str ());
    DpctlExecute (switchDeviceDl->GetDatapathId (), cmdUL.str ());
  }
}

void
QosCustomController::InstallUDPTrafficRules (Ptr<OFSwitch13Device> switchDevice,
                                          uint64_t trafficId, uint32_t group)
{ 
  NS_LOG_FUNCTION (this << switchDevice << trafficId << group);
  /*
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
  NS_ASSERT_MSG(group == 1 || group == 2, "Grupo não identificado!");
  std::ostringstream cmd;
  cmd << "flow-mod cmd=add,prio=128,idle=30,flags="<<OFPFF_SEND_FLOW_REM<<",table=0,cookie=" << GetUint64Hex (trafficId)
      << " eth_type=0x800,ip_src=" << srcip << ",ip_dst=" << dstip << ",ip_proto=17,udp_src=" << srcport << ",udp_dst=" << dstport
      << " write:group="<<group;
  info.cmd = cmd.str();
  DpctlExecute (switchDevice->GetDatapathId (), cmd.str ());
}

void
QosCustomController::MoveTrafficRules (Ptr<OFSwitch13Device> dstSwitchDevice,
                                    uint64_t trafficId)
{
  NS_LOG_FUNCTION (this << dstSwitchDevice << trafficId);

  //Recuperando informacoes do trafego pelo ID
  struct trafficInfo &info = m_trafficInfo[trafficId];
  Ipv4Address srcip = info.srcip;
  Ipv4Address dstip = info.dstip;
  uint16_t srcport = info.srcport;
  uint16_t dstport = info.dstport;

  *m_move->GetStream ()
    << boolalpha << right << fixed << setprecision (3)
    << setw (8)  << Simulator::Now().GetSeconds()
    << " " << setw (8)  << "SW"
    << " " << setw (8)  << "HW"
    << " " << setw (8) << GetUint64Hex(info.cookie)
    << " " << setw (10) << info.srcip
    << " " << setw (8) << info.dstip
    << " " << setw (8) << info.srcport
    << " " << setw (8) << info.dstport
    << " " << setw (5) << info.protocol
    << " " << setw (8) << info.numSwitches
    << " " << setw (14) << info.active
    << " " << setw (9) << info.inCache
    << " " << setw (8) << info.blocked
    << " " << setw (4) << info.direction
    //<< " " << setw (8) << info.second.cmd
    << " " << setw (20) << info.timeCreated.GetSeconds()
    << " " << setw (13) << info.timeFinished.GetSeconds()
    //<< " " << setw (8) << info.second.bytes
    << " " << setw (9) << info.expBytes
    << " " << setw (14) << info.rate.GetBitRate()
    << std::endl;

  // Instalando a nova regra no switch de destino.
  DpctlExecute(dstSwitchDevice->GetDpId(), info.cmd);

  // Alterando flags da struct
  info.numSwitches++;
  info.inCache = true;

  // Instalando nova regra com prioridade maior nos switches UL e DL
  std::ostringstream cmdUL, cmdDL;
  cmdUL << "flow-mod cmd=add,prio=512,idle=30,table=0,cookie=" << GetUint64Hex (trafficId)
        << " eth_type=0x800,ip_src=" << srcip << ",ip_dst=" << dstip << ",ip_proto=17,udp_src=" << srcport << ",udp_dst=" << dstport;
  cmdDL << "flow-mod cmd=add,prio=512,idle=30,table=0,cookie=" << GetUint64Hex (trafficId)
        << " eth_type=0x800,ip_src=" << dstip << ",ip_dst=" << srcip << ",ip_proto=17,udp_src=" << dstport << ",udp_dst=" << srcport;
  if(info.direction == 1)
  {
    cmdUL << " apply:output=" << ul2hwPort;
    cmdDL << " apply:output=" << dl2hwPort;
    DpctlExecute (switchDeviceUl->GetDatapathId (), cmdUL.str ());
    DpctlExecute (switchDeviceDl->GetDatapathId (), cmdDL.str ());
  }
  else
  {
    cmdUL << " apply:output=" << dl2hwPort;
    cmdDL << " apply:output=" << ul2hwPort;
    DpctlExecute (switchDeviceUl->GetDatapathId (), cmdDL.str ());
    DpctlExecute (switchDeviceDl->GetDatapathId (), cmdUL.str ());
  }
}

ofl_err
QosCustomController::HandleError (struct ofl_msg_error *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  char *msgStr = ofl_msg_to_string ((struct ofl_msg_header*)msg, 0);
  std::cout << "Switch DPID: " << swtch->GetDpId() << " OpenFlow error: " << msgStr << std::endl;
  free (msgStr);

  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err 
QosCustomController::HandleFlowRemoved (struct ofl_msg_flow_removed *msg, Ptr<const RemoteSwitch> swtch,
                                     uint32_t xid)
{
  NS_LOG_FUNCTION (this << msg << swtch << xid);
  NS_LOG_DEBUG("Regra expirada ou removida");
  uint64_t cookie = msg->stats->cookie;
  if(m_trafficInfo.count(cookie) == 1)
  {
    struct trafficInfo &tinfo = m_trafficInfo[cookie];
    tinfo.expBytes += msg->stats->byte_count;
    tinfo.numSwitches--;
    if(tinfo.numSwitches <= 0 && tinfo.active)
    {
      tinfo.active = false;
      m_regrasAtivas -= 1;
      tinfo.timeFinished = Simulator::Now();
    }
  }
  return 0;
}

void
QosCustomController::PrintLoadTimeout ()
{
  Simulator::Schedule (Seconds(15), &QosCustomController::PrintLoadTimeout, this);
  double totalusage = 0;
  double load = 0;
  for (size_t i = 0; i<m_activeSW; i++)
  {
    totalusage += switchDevicesSw.Get(i)->GetCpuUsage();
  }
  load = totalusage/m_activeSW;
  *m_log->GetStream ()
    << setw (8) << Simulator::Now().GetSeconds()
    << " " << setw (8) << m_activeSW
    << " " << setw (12) << load;
  *m_log->GetStream ()
    << " " << setw (10) << "Manteve"
    << " " << setw (8) << m_activeSW
    << std::endl;
}

void
QosCustomController::LoadControllerTimeout ()
{
  NS_LOG_FUNCTION (this);
  // Escalona a próxima operação de timeout para o controlador.
  Simulator::Schedule (m_loadTimeout, &QosCustomController::LoadControllerTimeout, this);
  // Carga
  double totalusage = 0;
  double load = 0;
  bool diminui = false;
  for (size_t i = 0; i<m_activeSW; i++)
  {
    totalusage += switchDevicesSw.Get(i)->GetCpuUsage();
  }
  load = totalusage/m_activeSW;
  *m_log->GetStream ()
    << setw (8) << Simulator::Now().GetSeconds()
    << " " << setw (8) << m_activeSW
    << " " << setw (12) << load;
  if(load >= m_maxSwLoad && m_activeSW < m_maxSW)
  {
    //A carga media é maior ou igual ao limite
    //Instancia um novo SW somente se o numero de switches ativos é menor que o maximo permitido
    NS_ASSERT_MSG(m_loadTimeout > m_newSwDelay, "Timeout menor do que o tempo de instanciar um switch!");
    Simulator::Schedule (m_newSwDelay, &QosCustomController::IncreaseActiveSW, this);
    std::cout << "Aumentando switches" << std::endl;
    
    *m_log->GetStream() << " " << setw (10) << "Aumenta"
    << " " << setw (8) << m_activeSW+1
    << std::endl;
    return;
  }
  else if (m_activeSW > 1)
  {
    //A carga media é menor ou igual ao limite, removendo um (ou mais) switches SW
    //Verificando se a carga é menor do que o limite mínimo
    load = totalusage/(m_activeSW-1);
    while (load < m_minSwLoad && m_activeSW > 1)
    {
      DecreaseActiveSW();
      load = totalusage/(m_activeSW-1);
      std::cout << "Diminuindo switches" << std::endl;
      diminui = true;
    }
  }
  *m_log->GetStream ()
    << " " << setw (10) << (diminui ? "Diminui" : "Manteve")
    << " " << setw (8) << m_activeSW
    << std::endl;
}

void
QosCustomController::MoveToSW (uint64_t cookie)
{
  NS_LOG_FUNCTION (this << cookie);

  struct trafficInfo &info = m_trafficInfo[cookie];
  info.inCache = false;

  for (size_t i = 0; i<m_activeSW; i++){
    //InstallUDPTrafficRules(switchDevicesSw.Get(i), cookie, direction);
    DpctlExecute(switchDevicesSw.Get(i)->GetDatapathId(), info.cmd);
    info.numSwitches++;
  }

  std::ostringstream cmd;
  cmd << "flow-mod cmd=del,cookie=" << GetUint64Hex (cookie) << ",cookie_mask=0xFFFFFFFFFFFFFFFF";
  DpctlExecute (switchDeviceUl->GetDatapathId (), cmd.str ());
  DpctlExecute (switchDeviceDl->GetDatapathId (), cmd.str ());
  DpctlExecute (switchDeviceHw->GetDatapathId (), cmd.str ());
}

void
QosCustomController::MoveTimeout ()
{
  NS_LOG_FUNCTION (this);
  // Escalona a próxima operação de timeout para o controlador.
  Simulator::Schedule (m_moveTimeout, &QosCustomController::MoveTimeout, this);

  // Vetor de pares vazio
	std::vector<std::pair<uint64_t,struct trafficInfo>> vec;
  // Copiando mapa para o vetor
	std::copy(m_trafficInfo.begin(),
			m_trafficInfo.end(),
			std::back_inserter<std::vector<std::pair<uint64_t,struct trafficInfo>>>(vec));
  // Ordenando vetor
  std::sort(vec.begin(), vec.end(),
			[](const std::pair<uint64_t,struct trafficInfo>& v1, const std::pair<uint64_t,struct trafficInfo>& v2) {
				return v1.second.rate > v2.second.rate;
			});

  // Verificando os recursos disponíveis no switch de HW:
  int tabHwFree =
    switchDeviceHw->GetFlowTableSize (0) * m_blockThs -
    switchDeviceHw->GetFlowTableEntries (0);

  for (auto &element : vec)
  {
    if (tabHwFree < 1)
    {
      // Parar se não houver mais recursos disponíveis no HW.
      break;
    }
    // Move os tráfegos ativos e não bloqueados do switch de SW para o switch de HW.
    if(!element.second.blocked && element.second.active && !element.second.inCache)
    {
      uint64_t cookie = element.second.cookie;
      NS_LOG_DEBUG ("Moving traffic ID " << cookie << " to HW switch.");
      MoveTrafficRules (switchDeviceHw, cookie);
      tabHwFree--;
    }
  }
}

void
QosCustomController::StatsTimeout ()
{
  NS_LOG_FUNCTION (this);

  // Escalona a próxima operação de timeout para o controlador.
  Simulator::Schedule (m_statsTimeout, &QosCustomController::StatsTimeout, this);

  //Atualiza as informaçoes de vazao e bytes enviados de cada trafego
  //Switches SW
  for (size_t i = 0; i<m_activeSW; i++)
  {
    struct datapath *datapath = switchDevicesSw.Get(i)->GetDatapathStruct ();
    struct flow_table *table = datapath->pipeline->tables[0];
    struct flow_entry *entry;

    // Percorrendo tabela e recuperando informações sobre os tráfegos.
    LIST_FOR_EACH (entry, struct flow_entry, match_node, &table->match_entries)
    {
      struct trafficInfo *tinfo;
      auto ret = m_trafficInfo.find(entry->stats->cookie);
      if (ret != m_trafficInfo.end ())
      {
        tinfo = &(ret->second);
        tinfo->bytes += entry->stats->byte_count;
      }
    }
  }
  //Switch HW
  struct datapath *datapath = switchDeviceHw->GetDatapathStruct ();
  struct flow_table *table = datapath->pipeline->tables[0];
  struct flow_entry *entry;
  LIST_FOR_EACH (entry, struct flow_entry, match_node, &table->match_entries)
  {
    struct trafficInfo *tinfo;
    auto ret = m_trafficInfo.find(entry->stats->cookie);
    if (ret != m_trafficInfo.end ())
    {
      tinfo = &(ret->second);
      tinfo->bytes += entry->stats->byte_count;
    }
  }

  for(auto &info : m_trafficInfo)
  {
    if(info.second.active)
    {
      Time active = Simulator::Now() - info.second.timeCreated;
      DataRate throughput ((info.second.bytes + info.second.expBytes) * 8 / active.GetSeconds ());
      info.second.rate = throughput;
      info.second.bytes = 0;
      //std::cout << "Traffic " << info.second.srcport << "->" << info.second.dstport << " with throughput " << throughput << std::endl;
    }
  }
}

void
QosCustomController::CreateGroups (Ptr<OFSwitch13Device> switchDevice, 
                                  std::vector<uint32_t> swports)
{
  //Cria os grupos com os switches
  for (size_t i=1; i<=swports.size(); i++){
    std::ostringstream cmd;
    cmd << "group-mod cmd=add,type=sel,group=" << i;
    for (size_t j=0;j<i;j++){
      cmd << " weight=1,port=any,group=any output=" << swports[j];
    }
    DpctlExecute (switchDevice->GetDpId(), cmd.str());
  }
  //Cria a regra padrao para enviar para o grupo
  std::ostringstream group;
  group << "flow-mod cmd=add,table=0,prio=1,cookie=" << GetUint64Hex (101)
        << " apply:group=" << m_activeSW;
  DpctlExecute (switchDevice->GetDpId(), group.str());
}

void
QosCustomController::IncreaseActiveSW ()
{
  NS_LOG_FUNCTION (this);
  uint32_t numSwitches = m_activeSW+1;
  if(numSwitches > m_maxSW)
  {
    NS_LOG_ERROR("Numero de switches SW maior do que o permitido!");
  }
  //Copia as regras dos switches SW para o novo
  for(auto &regra : m_trafficInfo)
  {
    if(regra.second.active)
    {
      DpctlExecute (switchDevicesSw.Get(numSwitches-1)->GetDpId(), regra.second.cmd);
      regra.second.numSwitches++;
    }
  }
  m_activeSW = numSwitches;
  //Atualizando regra padrao dos switches UL e DL
  std::ostringstream cmd;
  cmd << "flow-mod cmd=mod,table=0,cookie=" << GetUint64Hex (101) << ",cookie_mask=0xFFFFFFFFFFFFFFFF";
  cmd << " apply:group=" << m_activeSW;
  Simulator::Schedule (Seconds(1), &OFSwitch13Controller::DpctlExecute, this, switchDeviceUl->GetDatapathId (), cmd.str ());
  Simulator::Schedule (Seconds(1), &OFSwitch13Controller::DpctlExecute, this, switchDeviceDl->GetDatapathId (), cmd.str ());
  //Atualizando regra do ping para o switch SW
  std::ostringstream cmdULSW , cmdDLSW;
  cmdULSW << "flow-mod cmd=mod,prio=228,table=0,cookie=" << GetUint64Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_src=" << 65535 << ",udp_dst=" << 7001;
  cmdDLSW << "flow-mod cmd=mod,prio=228,table=0,cookie=" << GetUint64Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_dst=" << 65535 << ",udp_src=" << 7001;
  // Saidas de Uplink/Downlink.
  cmdULSW << " write:group="<<m_activeSW;
  cmdDLSW << " write:group="<<m_activeSW;
  DpctlExecute (switchDeviceUl->GetDatapathId (), cmdULSW.str ());
  DpctlExecute (switchDeviceDl->GetDatapathId (), cmdDLSW.str ());
}

void
QosCustomController::DecreaseActiveSW ()
{
  NS_LOG_FUNCTION (this);
  uint32_t numSwitches = m_activeSW - 1;

  if(numSwitches < 1)
  {
    NS_LOG_ERROR("Numero de switches SW menor do que o permitido!");
  }

  m_activeSW = numSwitches;
  //Atualizando regra padrao dos switches UL e DL
  std::ostringstream cmd;
  cmd << "flow-mod cmd=mod,table=0,cookie=" << GetUint64Hex (101) << ",cookie_mask=0xFFFFFFFFFFFFFFFF";
  cmd << " apply:group=" << m_activeSW;
  Simulator::Schedule (Seconds(1), &OFSwitch13Controller::DpctlExecute, this, switchDeviceUl->GetDatapathId (), cmd.str ());
  Simulator::Schedule (Seconds(1), &OFSwitch13Controller::DpctlExecute, this, switchDeviceDl->GetDatapathId (), cmd.str ());
  //Atualizando regra do ping para o switch SW
  std::ostringstream cmdULSW , cmdDLSW;
  cmdULSW << "flow-mod cmd=mod,prio=228,table=0,cookie=" << GetUint64Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_src=" << 65535 << ",udp_dst=" << 7001;
  cmdDLSW << "flow-mod cmd=mod,prio=228,table=0,cookie=" << GetUint64Hex (500)
        << " eth_type=0x800,ip_proto=17,udp_dst=" << 65535 << ",udp_src=" << 7001;
  // Saidas de Uplink/Downlink.
  cmdULSW << " write:group="<<m_activeSW;
  cmdDLSW << " write:group="<<m_activeSW;
  DpctlExecute (switchDeviceUl->GetDatapathId (), cmdULSW.str ());
  DpctlExecute (switchDeviceDl->GetDatapathId (), cmdDLSW.str ());
}

uint64_t
QosCustomController::CookieCreate (Ipv4Address ipsrc, Ipv4Address ipdst, uint16_t portsrc, uint16_t portdst, uint8_t protocol)
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

uint8_t
CookieGetProtocol (uint64_t cookie)
{
  cookie &= COOKIE_PROTOCOL_MASK;
  return static_cast<uint8_t> (cookie);
}

uint16_t
CookieGetPortDST (uint64_t cookie)
{
  cookie &= COOKIE_PORTDST_MASK;
  cookie >>= 8;
  return static_cast<uint16_t> (cookie);
}

uint16_t
CookieGetPortSRC (uint64_t cookie)
{
  cookie &= COOKIE_PORTSRC_MASK;
  cookie >>= 24;
  return static_cast<uint16_t> (cookie);
}

/*Ipv4Address
CookieGetIPDST (uint64_t cookie)
{
  cookie &= COOKIE_IPDST_MASK;
  cookie >>= 40;
  Ipv4Address ip ("10.0.0.0");
  Ipv4Mask mask (cookie);
  return Ipv4Address (cookie);
}

Ipv4Address
CookieGetIPSRC (uint64_t cookie)
{
  cookie &= COOKIE_IPSRC_MASK;
  cookie >>= 52;
  return static_cast<Ipv4Address> (cookie);
}*/


} // namespace ns3
