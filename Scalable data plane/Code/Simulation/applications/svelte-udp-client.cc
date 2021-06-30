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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * Author: João Victor Guimarães de Oliveira <joaoguimaraes@ice.ufjf.br>
 *         Pedro Clemente Pereira Bellotti <pedro.bellotti@ice.ufjf.br>
 *         Roberto Massi de Oliveira <rmassi@ice.ufjf.br>
 *         Alex Borges Vieira <alex.borges@ice.ufjf.br>
 *         Luciano J. Chaves <luciano.chaves@ice.ufjf.br>
 */

#include <iomanip>
#include <ns3/seq-ts-header.h>
#include "svelte-udp-client.h"


#undef NS_LOG_APPEND_CONTEXT
#define NS_LOG_APPEND_CONTEXT \
  std::clog << "[" << GetAppName ()                       \
            << " client teid " << GetTeidHex () << "] ";

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("SvelteUdpClient");
NS_OBJECT_ENSURE_REGISTERED (SvelteUdpClient);

TypeId
SvelteUdpClient::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::SvelteUdpClient")
    .SetParent<SvelteClient> ()
    .AddConstructor<SvelteUdpClient> ()

    // These attributes must be configured for the desired traffic pattern.
    .AddAttribute ("DataRate", "The data rate in on state.",
                    StringValue ("ns3::ExponentialRandomVariable[Mean=1024]"),
                    MakePointerAccessor (&SvelteUdpClient::m_cbrRng),
                    MakePointerChecker <RandomVariableStream>()
                    )
    .AddAttribute ("PktSize", "The size of packets sent in on state",
                    UintegerValue (512),
                    MakeUintegerAccessor (&SvelteUdpClient::m_pktSize),
                    MakeUintegerChecker<uint32_t> (1))
  ;
  return tid;
}

SvelteUdpClient::SvelteUdpClient ()
  : m_sendEvent (EventId ()),
  m_stopEvent (EventId ())
{
  NS_LOG_FUNCTION (this);
  if(m_log == 0){
    StringValue stringValue;
    GlobalValue::GetValueByName ("OutputPrefix", stringValue);
    std::string prefix = stringValue.Get ();
    m_log = Create<OutputStreamWrapper> (prefix+"iperfs.log", std::ios::out);
    // Print the header in output file.
    *m_log->GetStream ()
      << "Inicio(seg)"
      << std::setw(16) << "Duracao(seg)"
      << std::setw(16) << "Banda(Kbps)"    
      << std::setw(8) << "PCli"    
      << std::setw(8) << "PServ"
      << std::endl; 
  }
}

SvelteUdpClient::~SvelteUdpClient ()
{
  NS_LOG_FUNCTION (this);
}

void
SvelteUdpClient::Start ()
{
  NS_LOG_FUNCTION (this);

  // Schedule the ForceStop method to stop traffic based on traffic length.
  Time stop = GetTrafficLength ();
  //Simulator::Schedule (stop, &SvelteUdpClient::RequestOnePacket, this);

  m_stopEvent = Simulator::Schedule (stop, &SvelteUdpClient::ForceStop, this);
  NS_LOG_INFO ("Set traffic length to " << stop.GetSeconds () << "s.");

  m_cbrRate = DataRate (m_cbrRng->GetValue()*1000);
  while(m_cbrRate.GetBitRate() <= 500) //Garante trafegos de pelo menos 0.5kbps
  {
    m_cbrRate = DataRate (m_cbrRng->GetValue()*1000);
  }
  // Chain up to reset statistics, notify server, and fire start trace source.
  SvelteClient::Start ();

  // Start traffic.
  m_sendEvent.Cancel ();
  //Time send = Seconds (std::abs (m_pktInterRng->GetValue ()));
  Time send (Seconds (m_pktSize*8 / static_cast<double>(m_cbrRate.GetBitRate ()))); // Time till next packet
  m_sendEvent = Simulator::Schedule (send, &SvelteUdpClient::SendPacket, this);

  //Imprime informacoes sobre os trafegos
  *m_log->GetStream ()
      << std::fixed << std::setprecision(3) << Simulator::Now().GetSeconds()
      << std::setw(16) << stop.GetSeconds()
      << std::setw(16) << (double) m_cbrRate.GetBitRate()/1000    
      << std::setw(8) << m_localPort    
      << std::setw(8) << InetSocketAddress::ConvertFrom (m_serverAddress).GetPort ()
      << std::endl; 
}

void
SvelteUdpClient::DoDispose (void)
{
  NS_LOG_FUNCTION (this);

  m_stopEvent.Cancel ();
  m_sendEvent.Cancel ();
  m_log = 0;
  SvelteClient::DoDispose ();
}

void
SvelteUdpClient::RequestOnePacket ()
{
  NS_LOG_FUNCTION (this);
  Ptr<SvelteUdpServer> dc = dynamic_cast<SvelteUdpServer *> (PeekPointer (m_serverApp));
  dc->SendOnePacket();
}

void
SvelteUdpClient::ForceStop ()
{
  NS_LOG_FUNCTION (this);

  // Cancel (possible) pending stop event and stop the traffic.
  m_stopEvent.Cancel ();
  m_sendEvent.Cancel ();

  // Chain up to notify server.
  SvelteClient::ForceStop ();

  // Notify the stopped application one second later.
  Simulator::Schedule (Seconds (1), &SvelteUdpClient::NotifyStop, this, false);
}

void
SvelteUdpClient::StartApplication (void)
{
  NS_LOG_FUNCTION (this);

  NS_LOG_INFO ("Opening the UDP socket.");
  TypeId udpFactory = TypeId::LookupByName ("ns3::UdpSocketFactory");
  m_socket = Socket::CreateSocket (GetNode (), udpFactory);
  m_socket->Bind (InetSocketAddress (Ipv4Address::GetAny (), m_localPort));
  m_socket->Connect (InetSocketAddress::ConvertFrom (m_serverAddress));
  m_socket->SetRecvCallback (
    MakeCallback (&SvelteUdpClient::ReadPacket, this));
}

void
SvelteUdpClient::StopApplication ()
{
  NS_LOG_FUNCTION (this);

  if (m_socket != 0)
    {
      m_socket->Close ();
      m_socket->Dispose ();
      m_socket = 0;
    }
}

void
SvelteUdpClient::SendPacket ()
{
  NS_LOG_FUNCTION (this);

  Ptr<Packet> packet = Create<Packet> (m_pktSize);

  SeqTsHeader seqTs;
  seqTs.SetSeq (NotifyTx (packet->GetSize () + seqTs.GetSerializedSize ()));
  packet->AddHeader (seqTs);

  int bytes = m_socket->Send (packet);
  if (bytes == static_cast<int> (packet->GetSize ()))
    {
      NS_LOG_DEBUG ("Client TX " << bytes << " bytes with " <<
                    "sequence number " << seqTs.GetSeq ());
    }
  else
    {
      NS_LOG_ERROR ("Client TX error.");
    }

  // Schedule next packet transmission.
  Time send = Seconds (m_pktSize*8 / static_cast<double>(m_cbrRate.GetBitRate ())); // Time till next packet
  m_sendEvent = Simulator::Schedule (send, &SvelteUdpClient::SendPacket, this);
}

void
SvelteUdpClient::ReadPacket (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  // Receive the datagram from the socket.
  Ptr<Packet> packet = socket->Recv ();

  SeqTsHeader seqTs;
  packet->PeekHeader (seqTs);
  NotifyRx (packet->GetSize (), GetTeidHex(), GetPingTracking(), seqTs.GetTs ());
  NS_LOG_DEBUG ("Client RX " << packet->GetSize () << " bytes with " <<
                "sequence number " << seqTs.GetSeq ());
}

} // Namespace ns3
