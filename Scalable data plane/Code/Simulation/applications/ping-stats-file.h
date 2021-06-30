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
#ifndef PING_STATS_FILE_H
#define PING_STATS_FILE_H

#include <iomanip>
#include <iostream>
#include <ns3/core-module.h>
#include <ns3/network-module.h>

using namespace std;

namespace ns3 {

class PingStatsFile
{
public:
  PingStatsFile ();
  virtual ~PingStatsFile ();
  void SaveToFile(double seconds, string cookie, Time delay, Time jitter);
private:
  Ptr<OutputStreamWrapper> m_saida;  //!< Arquivo de log.
};

} // namespace ns3

#endif /* PING_STATS_FILE_H */