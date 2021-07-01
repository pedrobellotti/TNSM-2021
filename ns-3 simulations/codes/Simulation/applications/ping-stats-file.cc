/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2021 University of Juiz de Fora (UFJF)
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

#include "ping-stats-file.h"

using namespace std;

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("PingStatsFile");

PingStatsFile::PingStatsFile ()
{
  NS_LOG_FUNCTION (this);
  StringValue stringValue;
  GlobalValue::GetValueByName ("OutputPrefix", stringValue);
  std::string prefix = stringValue.Get ();
  m_saida = Create<OutputStreamWrapper> (prefix+"pingStats.log", ios::out); 
  // Print the header in output file.
  *m_saida->GetStream ()
    << boolalpha << right << fixed << setprecision (1)
    << "Time:s"
    << " " << setw (10) << "Cookie"
    << " " << setw (15) << "Delay:ns"
    << " " << setw (12) << "Jitter:ns"
    << std::endl;
}

PingStatsFile::~PingStatsFile ()
{
  NS_LOG_FUNCTION (this);
  m_saida = 0;
}

void PingStatsFile::SaveToFile (double seconds, string cookie, Time delay, Time jitter)
{
  NS_LOG_FUNCTION (this);
  *m_saida->GetStream ()
    << seconds
    << " " << setw (19) << cookie
    << " " << setw (10) << delay.GetDouble()
    << " " << setw (10) << jitter.GetDouble()
    << std::endl;
}

} // namespace ns3