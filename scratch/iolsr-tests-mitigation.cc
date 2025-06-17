#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/iolsr-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/netanim-module.h"
#include "ns3/udp-client-server-helper.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/energy-module.h"
#include "ns3/ipv4-routing-table-entry.h"
#include <string>
#include <sstream>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("StableNetworkRouteMod");


uint32_t macDataPkts = 0;
uint32_t macControlPkts = 0;

uint32_t g_helloCount = 0;
uint32_t g_tcCount = 0;
uint32_t g_midCount = 0;
uint32_t g_hnaCount = 0;

// uint32_t g_hnaCount = 0;

// Phase-based measurement variables
Ptr<FlowMonitor> g_baselineFlowMonitor;
Ptr<FlowMonitor> g_defenseFlowMonitor;
Ptr<FlowMonitor> g_attackFlowMonitor;

// Timing constants for the new phases
const double BASELINE_START = 61.0;
const double BASELINE_END = 80.0;
const double DEFENSE_ACTIVATION = 80.0;
const double DEFENSE_MEASUREMENT_START = 141.0;
const double DEFENSE_MEASUREMENT_END = 160.0;
const double ATTACK_ACTIVATION = 160.0;
const double ATTACK_MEASUREMENT_START = 221.0;
const double ATTACK_MEASUREMENT_END = 240.0;
const double MEASUREMENT_DURATION = 20.0;

// Base output directory for the three scenarios
std::string g_outputBaseDir = "./simulations/features/";
uint32_t g_currentRun = 1;


void MacTxCallback(std::string context, Ptr<const Packet> packet) {
    macDataPkts++;
}

void MacTxControlCallback(std::string context, Ptr<const Packet> packet) {
    macControlPkts++;
}

void
TraceOlsrPacket (Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface)
{
  Ptr<Packet> pktCopy = packet->Copy ();

  Ipv4Header ipHeader;
  pktCopy->RemoveHeader (ipHeader);

  if (ipHeader.GetProtocol () != 17) // Not UDP
    return;

  UdpHeader udpHeader;
  pktCopy->RemoveHeader (udpHeader);

  if (udpHeader.GetDestinationPort () != 698)
    return;

  // Parse OLSR packet
  iolsr::PacketHeader olsrHeader;
  pktCopy->RemoveHeader (olsrHeader);

  iolsr::MessageHeader msg;

  while (pktCopy->GetSize () > 0)
    {
      if (!pktCopy->RemoveHeader (msg))
        break;

      switch (msg.GetMessageType ())
        {
        case iolsr::MessageHeader::HELLO_MESSAGE:
          ++g_helloCount;
          break;
        case iolsr::MessageHeader::TC_MESSAGE:
          ++g_tcCount;
          break;
        case iolsr::MessageHeader::MID_MESSAGE:
          ++g_midCount;
          break;
        case iolsr::MessageHeader::HNA_MESSAGE:
          ++g_hnaCount;
          break;
        default:
          break;
        }
    }
}
 
static void PrintCountFakeNodes(NodeContainer* cont){
/*
Count the number of nodes that require fake/fictive neighbor
A fake node is required when there is a risk that some node will execute an isolation attack
*/
	//ns3::iolsr::RoutingProtocol rp;
	unsigned int count = 0;
	std::cout << "Nodes who are required to advertise fictive: " ;
	for (unsigned int i=0;i<cont->GetN();++i){
		Ptr<RoutingProtocol> pt = cont->Get(i)->GetObject<RoutingProtocol>();
		//NS_LOG_INFO("Node id: " << i << "\tTime: " << Simulator::Now().GetSeconds() << "\tRequireFake? " << pt->RequireFake());
		if (pt->RequireFake()){
			++count;
			std::cout << i << ", ";
		} ;
	}
	std::cout << std::endl;
	NS_LOG_INFO("Total fakes required: " << count << " out of " << cont->GetN());
	std::cout << "Fictives req.: " << count << std::endl;
}

static void PrintNodesDeclaredFictive(NodeContainer* cont){

	//ns3::iolsr::RoutingProtocol rp;
	unsigned int count = 0;
	std::cout << "Nodes who declared fictive: ";
	for (unsigned int i=0;i<cont->GetN();++i){
		Ptr<RoutingProtocol> pt = cont->Get(i)->GetObject<RoutingProtocol>();
		//NS_LOG_INFO("Node id: " << i << "\tTime: " << Simulator::Now().GetSeconds() << "\tRequireFake? " << pt->RequireFake());
		
		if (pt->returnDeclaredFictive()){
			++count;
			std::cout << i << ", ";
		} 
	}
	std::cout << std::endl;
	NS_LOG_INFO("Total nodes declaring fictives: " << count << " out of " << cont->GetN());
	std::cout << "Total nodes declaring fictives: " << count << std::endl;
}

static void PrintMprFraction(NodeContainer* cont){
/*
For each node get the fraction of it's MPR (using FractionOfMpr: number of MPRs / number of neighbors) and sum all the fractions
Output a message of the fraction of MPR over all nodes
*/
	// double sum = 0;
	// for (unsigned int i=0;i<cont->GetN();++i){
	// 	Ptr<RoutingProtocol> pt = cont->Get(i)->GetObject<RoutingProtocol>();
	// 	//NS_LOG_INFO("Node id: " << i << "\tTime: " << Simulator::Now().GetSeconds() << "\tFraction: " << pt->FractionOfMpr());
	// 	sum += pt->FractionOfMpr();
	// }
	// NS_LOG_INFO("Total fraction of MPR: " << sum / (double) cont->GetN());
	// NS_LOG_INFO(sum / (double) cont->GetN());
	// //... NS_LOG_INFO broke. Using cout...
	// //std::cout << "Total fraction of MPR: " << sum / (double) cont->GetN() << std::endl;
	// std::cout << "MPR: " << (sum / (double) cont->GetN()) << std::endl; 

	double sum = 0;
	uint32_t countTotalNeighbors = 0;
	for (unsigned int i=0;i<cont->GetN();++i){
		Ptr<RoutingProtocol> pt = cont->Get(i)->GetObject<RoutingProtocol>();
		//NS_LOG_INFO("Node id: " << i << "\tTime: " << Simulator::Now().GetSeconds() << "\tFraction: " << pt->FractionOfMpr());
		sum += pt->getMprSize();
		countTotalNeighbors  += pt->getNeighborsSize();
	}
	// NS_LOG_INFO("Total fraction of MPR: " << sum / (double) cont->GetN());
	// NS_LOG_INFO(sum / (double) cont->GetN());
	NS_LOG_INFO("Total fraction of MPR: " << sum / (double) countTotalNeighbors);
	NS_LOG_INFO(sum / (double) countTotalNeighbors);
	//... NS_LOG_INFO broke. Using cout...
	//std::cout << "Total fraction of MPR: " << sum / (double) cont->GetN() << std::endl;
	std::cout << "Total MPRs chosen: " << sum << std::endl;
	std::cout << "Total Neighbors: " << countTotalNeighbors << std::endl;

	std::cout << "Avg MPR fraction: " << (sum / countTotalNeighbors) << std::endl;
}

static void PrintMprs(NodeContainer* cont){
	uint32_t totalMprs = 0;
	MprSet allMPRs = cont->Get(0)->GetObject<RoutingProtocol>()->getMprSet();
	for (unsigned int i=1;i<cont->GetN();++i){
		MprSet currentMprSet = cont->Get(i)->GetObject<RoutingProtocol>()->getMprSet();
		allMPRs.insert(currentMprSet.begin(), currentMprSet.end());
		
	// 	sumLsr += pt->tcPowerLevel(true);
	// 	sumOlsr += pt->tcPowerLevel(false);
	// }
	// //NS_LOG_INFO("TC Level: " << sumOlsr / (double) cont->GetN() << " (lsr: " << sumLsr / (double) cont->GetN() << ")");
	// std::cout << "TC Level: " << sumOlsr / (double) cont->GetN() << " \nlsr: " << sumLsr / (double) cont->GetN() << "\n";
	}
	totalMprs = allMPRs.size();
	std::cout << "Total MPRs: " << totalMprs << std::endl;
	std::cout << "MPR sub-network nodes: " << std::endl;
	for (MprSet::const_iterator it = allMPRs.begin(); it != allMPRs.end(); ++it){
			std::cout << *it << ", ";
		}
	std::cout << std::endl;
}

static void Print2hopNeighborsOfVictim(NodeContainer* cont){
	Ptr<RoutingProtocol> victimNode = cont->Get(0)->GetObject<RoutingProtocol>();

	const NeighborSet& neighbors = victimNode->getNeighborSet();
	const TwoHopNeighborSet& twoHops = victimNode->getTwoHopNeighborSet();
	std::list<Ipv4Address> oneHopsInList;
	std::list<Ipv4Address> twoHopsInList;
	for (NeighborSet::const_iterator it = neighbors.begin(); it != neighbors.end(); ++it){
		//if (it->twoHopNeighborAddr == m_mainAddress) continue;
      //std::cout << it->twoHopNeighborAddr << ", " ;
	  oneHopsInList.push_back(it->neighborMainAddr);
    }
	for (TwoHopNeighborSet::const_iterator it = twoHops.begin(); it != twoHops.end(); ++it){
		//if (it->twoHopNeighborAddr == m_mainAddress) continue;
      //std::cout << it->twoHopNeighborAddr << ", " ;
	  twoHopsInList.push_back(it->twoHopNeighborAddr);
    }
std::cout << "1Hop from victim: " << std::endl;
	oneHopsInList.sort();
	oneHopsInList.unique();
	for (std::list<Ipv4Address>::iterator it = oneHopsInList.begin(); it != oneHopsInList.end(); ++it){
		std::cout << *it << ", " ;
	}
	std::cout << std::endl;

	std::cout << "2Hops from victim: " << std::endl;
	twoHopsInList.sort();
	twoHopsInList.unique();
	for (std::list<Ipv4Address>::iterator it = twoHopsInList.begin(); it != twoHopsInList.end(); ++it){
		std::cout << *it << ", " ;
	}
	std::cout << std::endl;
}

static void PrintC6Detection(NodeContainer* cont){
/*
Count the number of nodes that detected themselves as part of a c6 cycle topology.
*/
	//ns3::iolsr::RoutingProtocol rp;
	unsigned int count = 0;
	std::cout << "Nodes detected as part of c6: ";
	for (unsigned int i=0;i<cont->GetN();++i){
		Ptr<RoutingProtocol> pt = cont->Get(i)->GetObject<RoutingProtocol>();
		//NS_LOG_INFO("Node id: " << i << "\tTime: " << Simulator::Now().GetSeconds() << "\tRequireFake? " << pt->RequireFake());
		if (pt->returnDetectedInC6()){
			std::cout << i << ", ";
			++count;
		}
	}
	NS_LOG_INFO("Total nodes in c6: " << count << " out of " << cont->GetN());
	std::cout << std::endl;
	std::cout << "Num. of nodes detected as part of c6: " << count << std::endl;
}

static void PrintNodeOutputLog(NodeContainer* cont, uint32_t nodeID){ //!!
	Ptr<RoutingProtocol> pt = cont->Get(nodeID)->GetObject<RoutingProtocol>();
	std::string log = pt->getOutputLog();
	std::cout << "Log for node " << nodeID << ": " << std::endl;
	std::cout << log << std::endl << std::endl;
}

static void PrintRiskyFraction(NodeContainer* cont, Ipv4Address ignore = Ipv4Address("0.0.0.0")){
	/*
	*/
	double sum = 0;
	for (unsigned int i=0;i<cont->GetN();++i){
		Ptr<RoutingProtocol> pt = cont->Get(i)->GetObject<RoutingProtocol>();
		sum += pt->FractionOfNodesMarkedAsRisky(ignore);
	}
	std::cout << "Risky nodes: " << sum << std::endl;
}

static void PrintTcPowerLevel(NodeContainer* cont){
	double sumLsr = 0;
	double sumOlsr = 0;
	for (unsigned int i=0;i<cont->GetN();++i){
		Ptr<RoutingProtocol> pt = cont->Get(i)->GetObject<RoutingProtocol>();
		sumLsr += pt->tcPowerLevel(true);
		sumOlsr += pt->tcPowerLevel(false);
	}
	//NS_LOG_INFO("TC Level: " << sumOlsr / (double) cont->GetN() << " (lsr: " << sumLsr / (double) cont->GetN() << ")");
	std::cout << "TC Level: " << sumOlsr / (double) cont->GetN() << " \nlsr: " << sumLsr / (double) cont->GetN() << "\n";
}

static size_t getTcPowerLevel(NodeContainer* cont){
	double sumOlsr = 0;
	for (unsigned int i=0;i<cont->GetN();++i){
		Ptr<RoutingProtocol> pt = cont->Get(i)->GetObject<RoutingProtocol>();
		sumOlsr += pt->tcPowerLevel(false);
	}
	return sumOlsr / (double) cont->GetN();
}

static void ExecuteIsolationAttack(NodeContainer* cont){
	// Make it pick a node at random later...
	Ipv4Address target = cont->Get(2)->GetObject<RoutingProtocol>()->ExecuteIsolationAttack();
	target.IsBroadcast(); // Kill the unused warning
	//NS_LOG_INFO("Executing node isolation attack on: " << target);
	//NS_LOG_INFO("Attacker address: " << cont->Get(2)->GetObject<Ipv4>()->GetAddress(1,0));
	//NS_LOG_INFO("Victim  test: " << cont->Get(25)->GetObject<Ipv4>()->GetAddress(1,0));
	std::cout << "Executing node isolation attack on: " << target << std::endl;
	std::cout << "Attacker address: " << cont->Get(2)->GetObject<Ipv4>()->GetAddress(1,0) << std::endl;
}

static void ExecuteIsolationAttackMassive(NodeContainer* cont){
	// Let the first 30% nodes attack and see what happens
	for (uint32_t i=5;i<cont->GetN() * 0.3 + 5; ++i){
		// cont->Get(i)->GetObject<RoutingProtocol>()->ExecuteIsolationAttack();
		cont->Get(i)->GetObject<RoutingProtocol>()->ExecuteIsolationAttack(Ipv4Address("10.0.0.1"));
	}
}

static void ExecuteIsolationAttackByNeighbor(NodeContainer* nodes, Ipv4Address target){
	bool found = false;
	for (uint32_t i=3; i< nodes->GetN(); ++i){
		if (nodes->Get(i)->GetObject<RoutingProtocol>()->isItNeighbor(target)){
			found = true;
			nodes->Get(i)->GetObject<RoutingProtocol>()->ExecuteIsolationAttack(target);
			std::cout << "Attacker found. Attacking from node id: " << i << std::endl;
			break;
		}
	}
	if(!found){
		std::cout << "Attacker not available. *** Terminated *** " << std::endl;
		Simulator::Stop();
	}
}

static void PercentageWithFullConnectivity(NodeContainer* cont){
	uint32_t count = 0;
	for (uint32_t i=0;i<cont->GetN();++i){
		uint32_t routingTableSize = cont->Get(i)->GetObject<RoutingProtocol>()->getRoutingTableSize();
		MprSet nodeMprSet = cont->Get(i)->GetObject<RoutingProtocol>()->getMprSet();
		
		std::cout << "Node id: "<< i << ", nodes in routing table: " << routingTableSize << ".   MPRs(" << nodeMprSet.size() <<"): ";
		for (MprSet::const_iterator it = nodeMprSet.begin(); it != nodeMprSet.end(); ++it){
			std::cout << *it << ", ";
		}
		std::cout << std::endl;
		if (routingTableSize == cont->GetN() - 1) {
			++count;
		}
	}
	double result = count / (double) cont->GetN();
	std::cout << "Routing Percentage: " << result << "\n";
	//Simulator::Schedule(Seconds (10), &PercentageWithFullConnectivity, cont);
}

static void ActivateFictiveDefence(NodeContainer* cont){
	for (unsigned int i=0; i < cont->GetN(); ++i){
		cont->Get(i)->GetObject<RoutingProtocol>()->activateFictiveDefence();
	}
}

static void ActivateFictiveMitigation(NodeContainer* cont){
	for (unsigned int i=0; i < cont->GetN(); ++i){
		cont->Get(i)->GetObject<RoutingProtocol>()->activateFictiveMitigation();
	}
	//std::cout << "Enabled new mitigation defence on all nodes." << std::endl;
}

static void ReportNumReceivedPackets(Ptr<UdpServer> udpServer){
	std::cout << "Packets: " << udpServer->GetReceived() << std::endl;
}

static void AbortIfNotReceivedPackets(Ptr<UdpServer> udpServer){
	if (udpServer->GetReceived() == 0){
		std::cout << "* Received 0 packets, terminating." << std::endl;
		Simulator::Stop();
	}
}

static void AssertConnectivity(NodeContainer* cont){
	for (unsigned int i=0; i < cont->GetN(); ++i){
		if (cont->Get(i)->GetObject<RoutingProtocol>()->getRoutingTableSize() != cont->GetN() - 1) {
			std::cout << "*** Assert connectivity failed, terminated." << std::endl;
			Simulator::Stop();
		}
	}
	//if (cont->Get(0)->GetObject<RoutingProtocol>()->getRoutingTableSize() != cont->GetN() - 1) {
	//	Simulator::Stop();
	//}
}
static void AbortOnNeighbor (Ptr<Node> node, Ipv4Address address){
	if (node->GetObject<RoutingProtocol>()->isItNeighbor(address)){
		std::cout << "*** Sending node of udp packets is a neighbor to victim. Terminated." << std::endl;
		Simulator::Stop();
	}
}

static void TrackTarget (Ptr<Node> target, Ptr<Node> tracker){
	Vector vec = target->GetObject<MobilityModel>()->GetPosition();
	vec.x += 8;
	vec.y += 0;
	tracker->GetObject<MobilityModel>()->SetPosition(vec);
}

static void PrintTables(Ptr<Node> n, std::string fname){
	std::ofstream o;
	o.open((std::string("_TwoHop") + fname + std::string(".txt")).c_str());
	const TwoHopNeighborSet &two = n->GetObject<RoutingProtocol>()->getTwoHopNeighborSet();
	for (TwoHopNeighborSet::const_iterator it = two.begin(); it!=two.end(); ++it){
		o << *it << "\n";
	}
	o.close();
	o.open((std::string("_Topology") + fname + std::string(".txt")).c_str());
	const TopologySet &tp = n->GetObject<RoutingProtocol>()->getTopologySet();
	for (TopologySet::const_iterator it = tp.begin(); it!=tp.end(); ++it){
		o << *it << "\n";
	}
	o.close();
	o.open((std::string("_Neighbor") + fname + std::string(".txt")).c_str());
	const NeighborSet &nei = n->GetObject<RoutingProtocol>()->getNeighborSet();
	for (NeighborSet::const_iterator it = nei.begin(); it!=nei.end(); ++it){
		o << *it << "\n";
	}
	o.close();
}

static void IneffectiveNeighorWrite(NodeContainer *cont){
	std::ofstream o;
	o.open ("_mpr.txt");
	//For each node write a list of it's MPRs
	for (unsigned int i=0; i< cont->GetN(); ++i){
		const MprSet mpr = cont->Get(i)->GetObject<RoutingProtocol>()->getMprSet();
		o << cont->Get(i)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << ":";
		for (MprSet::const_iterator it = mpr.begin(); it != mpr.end(); ++it){
			o << *it << ",";
		}
		o << "\n";
	}
	o.close();
	o.open ("_neighbors.txt");
	//For each node write a list of it's 1-hop neighbors and their address
	for (unsigned int i=0; i< cont->GetN(); ++i){
		const NeighborSet neighbor = cont->Get(i)->GetObject<RoutingProtocol>()->getNeighborSet();
		o << cont->Get(i)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << ":";
		for (NeighborSet::const_iterator it = neighbor.begin(); it != neighbor.end(); ++it){
			o << it->neighborMainAddr << ",";
		}
		o << "\n";
	}
	o.close();

}

bool bIsolationAttackBug;
bool bEnableFictive;
bool bIsolationAttackNeighbor;
bool bEnableFictiveMitigation;

// static void PrintSimStats(NodeContainer* cont){

// 	std::cout << "@@   New Simulation   @@" << std::endl;
// 	std::cout << "Seed RngRun: " << RngSeedManager::GetRun() << std::endl;
// 	if(bIsolationAttackBug || bIsolationAttackNeighbor){
// 	std::cout << "Attack: ON" << std::endl;
// 	} else{
// 		std::cout << "Attack: OFF" << std::endl;
// 	}
// 	if(bEnableFictive || bEnableFictiveMitigation){
// 		std::cout << "Defence: ON" << std::endl;
// 	} else{
// 		std::cout << "Defence: OFF" << std::endl;
// 	}

	
// }

void ExtractAndLogMetrics(Ptr<FlowMonitor> flowMon, FlowMonitorHelper &flowHelper, NodeContainer &nodes, const char* filename) {
    std::ofstream file(filename);
    file << "Metric,Value" << std::endl;

    flowMon->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = flowMon->GetFlowStats();

    double totalTxPackets = 0, totalRxPackets = 0, totalLostPackets = 0, totalDelay = 0;
    double totalThroughput = 0, totalJitter = 0, totalHopCount = 0, totalRoutingPackets = 0;
    double totalEnergyConsumed = 0;

    std::map<FlowId, FlowMonitor::FlowStats>::iterator it;
    for (it = stats.begin(); it != stats.end(); ++it) {
        totalTxPackets += it->second.txPackets;
        totalRxPackets += it->second.rxPackets;
        totalLostPackets += (it->second.txPackets - it->second.rxPackets);
        totalDelay += it->second.delaySum.GetSeconds();
        totalJitter += it->second.jitterSum.GetSeconds();
        totalHopCount += (it->second.timesForwarded + 1);
        totalThroughput += it->second.rxBytes * 8.0 / (it->second.timeLastRxPacket.GetSeconds() - it->second.timeFirstTxPacket.GetSeconds()) / 1e6;
    }

    double pdr = (totalTxPackets > 0) ? (totalRxPackets / totalTxPackets) * 100 : 0;
    double plr = (totalTxPackets > 0) ? (totalLostPackets / totalTxPackets) * 100 : 0;
    double avgDelay = (totalRxPackets > 0) ? (totalDelay / totalRxPackets) : 0;
    double avgJitter = (totalRxPackets > 0) ? (totalJitter / totalRxPackets) : 0;
    double avgHopCount = (totalRxPackets > 0) ? (totalHopCount / totalRxPackets) : 0;

    NodeContainer::Iterator i;
    for (i = nodes.Begin(); i != nodes.End(); ++i) {
        Ptr<iolsr::RoutingProtocol> iolsr = (*i)->GetObject<iolsr::RoutingProtocol>();
        if (iolsr) {
            totalRoutingPackets += iolsr->getRoutingTableSize();
        }

        Ptr<EnergySource> energySource = (*i)->GetObject<EnergySource>();
        if (energySource) {
		totalEnergyConsumed += (energySource->GetInitialEnergy() - energySource->GetRemainingEnergy());
        }
    }

    double avgSpeed = 0;
    for (i = nodes.Begin(); i != nodes.End(); ++i) {
        Ptr<MobilityModel> mobilityModel = (*i)->GetObject<MobilityModel>();
        Vector velocity = mobilityModel->GetVelocity();
        avgSpeed += std::sqrt(std::pow(velocity.x, 2) + std::pow(velocity.y, 2) + std::pow(velocity.z, 2));
    }
    avgSpeed /= nodes.GetN();

    double energyEfficiency = (totalEnergyConsumed > 0) ? totalThroughput / totalEnergyConsumed : 0;
    double normalizedRoutingLoad = (totalRxPackets > 0) ? totalRoutingPackets / totalRxPackets : 0;
    double avgTcRows = getTcPowerLevel(&nodes);
    double routingOverhead = (totalRxPackets > 0) ? totalRoutingPackets / totalRxPackets : 0;

    double macOverhead = (macDataPkts + macControlPkts > 0)
                     ? static_cast<double>(macControlPkts) / (macDataPkts + macControlPkts)
                     : 0;

    file << "Packet Delivery Ratio (%)," << pdr << std::endl;
    file << "Packet Loss Ratio (%)," << plr << std::endl;
    file << "End-to-End Delay (s)," << avgDelay << std::endl;
    file << "Jitter (s)," << avgJitter << std::endl;
    file << "Throughput (Mbps)," << totalThroughput << std::endl;
    file << "Average Hop Count," << avgHopCount << std::endl;
    file << "Total Energy Consumed (J)," << totalEnergyConsumed << std::endl;
    file << "Average Node Speed (m/s)," << avgSpeed << std::endl;
    file << "Energy Efficiency (bits/Joule)," << energyEfficiency << std::endl;
    file << "Normalized Routing Load," << normalizedRoutingLoad << std::endl;
    file << "Average TC Packet Rows," << avgTcRows << std::endl;
    file << "Routing Overhead," << routingOverhead << std::endl;
    file << "MAC Layer Overhead," << macOverhead << std::endl;
    file << "HELLO packets," << g_helloCount / nodes.GetN() << std::endl;
    file << "TC packets," << g_tcCount / nodes.GetN() << std::endl;
    file << "MID packets," << g_midCount / nodes.GetN() << std::endl;
    file << "HNA packets," << g_hnaCount / nodes.GetN() << std::endl;

    file.close();
    std::cout << "Metrics written to " << filename << std::endl;
}

// Function to create output directories
static void CreateOutputDirectories() {
    system(("mkdir -p " + g_outputBaseDir + "baseline/").c_str());
    system(("mkdir -p " + g_outputBaseDir + "defense/").c_str());
    system(("mkdir -p " + g_outputBaseDir + "defense_vs_attack/").c_str());
}

// Convert number to string (C++11 compatible)
std::string ToString(uint32_t value) {
    std::ostringstream oss;
    oss << value;
    return oss.str();
}

std::string ToString(double value) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6) << value;
    return oss.str();
}

// Function to save metrics for a specific scenario (C++11 compatible with all metrics)
static void SaveScenarioMetrics(const std::string& scenario, Ptr<FlowMonitor> flowMon, 
                               FlowMonitorHelper& flowHelper, NodeContainer& nodes, 
                               double startTime, double endTime) {
    
    std::string filename = g_outputBaseDir + scenario + "/metrics_output-" + 
                          ToString(g_currentRun) + ".csv";
    
    std::ofstream file(filename.c_str());
    if (!file.is_open()) {
        NS_LOG_ERROR("Cannot open file: " << filename);
        return;
    }
    
    // Write CSV header
    file << "Scenario,Metric,Value,StartTime,EndTime,Duration\n";
    file << std::fixed << std::setprecision(6);
    
    // Calculate metrics using your existing ExtractAndLogMetrics logic
    if (flowMon) {
        flowMon->CheckForLostPackets();
        Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
        std::map<FlowId, FlowMonitor::FlowStats> stats = flowMon->GetFlowStats();

        double totalTxPackets = 0, totalRxPackets = 0, totalLostPackets = 0, totalDelay = 0;
        double totalThroughput = 0, totalJitter = 0, totalHopCount = 0;
        double measurementDuration = endTime - startTime;

        // C++11 compatible iteration
        std::map<FlowId, FlowMonitor::FlowStats>::iterator it;
        for (it = stats.begin(); it != stats.end(); ++it) {
            totalTxPackets += it->second.txPackets;
            totalRxPackets += it->second.rxPackets;
            totalLostPackets += (it->second.txPackets - it->second.rxPackets);
            totalDelay += it->second.delaySum.GetSeconds();
            totalJitter += it->second.jitterSum.GetSeconds();
            totalHopCount += (it->second.timesForwarded + 1);
            if (it->second.timeLastRxPacket.GetSeconds() > it->second.timeFirstTxPacket.GetSeconds()) {
                totalThroughput += it->second.rxBytes * 8.0 / 
                    (it->second.timeLastRxPacket.GetSeconds() - it->second.timeFirstTxPacket.GetSeconds()) / 1e6;
            }
        }

        double pdr = (totalTxPackets > 0) ? (totalRxPackets / totalTxPackets) * 100 : 0;
        double plr = (totalTxPackets > 0) ? (totalLostPackets / totalTxPackets) * 100 : 0;
        double avgDelay = (totalRxPackets > 0) ? (totalDelay / totalRxPackets) : 0;
        double avgJitter = (totalRxPackets > 0) ? (totalJitter / totalRxPackets) : 0;
        double avgHopCount = (totalRxPackets > 0) ? (totalHopCount / totalRxPackets) : 0;

        // Calculate additional network metrics
        double totalEnergyConsumed = 0.0;
        double totalRoutingPackets = 0.0;
        double avgTcRows = 0.0;
        
        // Calculate energy consumption (if energy sources are available)
        for (uint32_t i = 0; i < nodes.GetN(); ++i) {
            Ptr<EnergySource> energySource = nodes.Get(i)->GetObject<EnergySource>();
            if (energySource) {
                totalEnergyConsumed += (energySource->GetInitialEnergy() - energySource->GetRemainingEnergy());
            }
            
            // Get routing table size and TC power level
            Ptr<RoutingProtocol> routingProtocol = nodes.Get(i)->GetObject<RoutingProtocol>();
            if (routingProtocol) {
                totalRoutingPackets += routingProtocol->getRoutingTableSize();
                avgTcRows += routingProtocol->tcPowerLevel(false);
            }
        }
        
        // Calculate derived metrics
        double energyEfficiency = (totalEnergyConsumed > 0 && totalRxPackets > 0) ? 
                                 (totalRxPackets * 8.0) / totalEnergyConsumed : 0;
        double normalizedRoutingLoad = (totalRxPackets > 0) ? 
                                      totalRoutingPackets / totalRxPackets : 0;
        double routingOverhead = (totalRxPackets > 0) ? 
                                totalRoutingPackets / totalRxPackets : 0;
        double macOverhead = (macDataPkts + macControlPkts > 0) ?
                            (double)macControlPkts / (macDataPkts + macControlPkts) : 0;
        avgTcRows = avgTcRows / nodes.GetN();

        // Write basic network performance metrics
        file << scenario << ",PacketDeliveryRatio," << ToString(pdr) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",PacketLossRatio," << ToString(plr) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",EndToEndDelay," << ToString(avgDelay) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",Jitter," << ToString(avgJitter) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",Throughput," << ToString(totalThroughput) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",AverageHopCount," << ToString(avgHopCount) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        
        // Write additional network performance metrics
        file << scenario << ",TotalEnergyConsumed," << ToString(totalEnergyConsumed) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",EnergyEfficiency," << ToString(energyEfficiency) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",NormalizedRoutingLoad," << ToString(normalizedRoutingLoad) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",RoutingOverhead," << ToString(routingOverhead) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",MACLayerOverhead," << ToString(macOverhead) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",AverageTCPacketRows," << ToString(avgTcRows) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        
        // Add OLSR packet rates (convert total counts to per-second rates)
        file << scenario << ",HELLOPacketsPerSec," << ToString(g_helloCount / measurementDuration) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",TCPacketsPerSec," << ToString(g_tcCount / measurementDuration) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",MIDPacketsPerSec," << ToString(g_midCount / measurementDuration) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",HNAPacketsPerSec," << ToString(g_hnaCount / measurementDuration) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        
        // Add MAC packet rates
        file << scenario << ",MACDataPacketsPerSec," << ToString(macDataPkts / measurementDuration) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
        file << scenario << ",MACControlPacketsPerSec," << ToString(macControlPkts / measurementDuration) << "," 
             << ToString(startTime) << "," << ToString(endTime) << "," << ToString(measurementDuration) << "\n";
    }
    
    file.close();
    NS_LOG_INFO("Scenario metrics saved to: " << filename);
}

// Function to reset OLSR packet counters
static void ResetOlsrCounters() {
    g_helloCount = 0;
    g_tcCount = 0;
    g_midCount = 0;
    g_hnaCount = 0;
    macDataPkts = 0;
    macControlPkts = 0;
    NS_LOG_INFO("OLSR counters reset at time " << Simulator::Now().GetSeconds());
}

static void EndBaselineMeasurement(NodeContainer* nodes) {
    NS_LOG_INFO("Ending baseline measurement at " << Simulator::Now().GetSeconds() << "s");
    
    FlowMonitorHelper flowHelper;
    SaveScenarioMetrics("baseline", g_baselineFlowMonitor, flowHelper, *nodes, 
                       BASELINE_START, BASELINE_END);
    
    // Clean up
    g_baselineFlowMonitor = 0; // C++11 compatible null assignment
}

// PHASE 2: Baseline measurement functions
static void StartBaselineMeasurement(NodeContainer* nodes) {
    NS_LOG_INFO("Starting baseline measurement at " << Simulator::Now().GetSeconds() << "s");
    ResetOlsrCounters();
    
    // Create new FlowMonitor for baseline phase
    FlowMonitorHelper flowHelper;
    g_baselineFlowMonitor = flowHelper.InstallAll();
    
    // Schedule end of baseline measurement
    Simulator::Schedule(Seconds(MEASUREMENT_DURATION), &EndBaselineMeasurement, nodes);
}

static void EndDefenseMeasurement(NodeContainer* nodes) {
    NS_LOG_INFO("Ending defense measurement at " << Simulator::Now().GetSeconds() << "s");
    
    FlowMonitorHelper flowHelper;
    SaveScenarioMetrics("defense", g_defenseFlowMonitor, flowHelper, *nodes, 
                       DEFENSE_MEASUREMENT_START, DEFENSE_MEASUREMENT_END);
    
    // Clean up
    g_defenseFlowMonitor = 0; // C++11 compatible null assignment
}

// PHASE 5: Defense measurement functions
static void StartDefenseMeasurement(NodeContainer* nodes) {
    NS_LOG_INFO("Starting defense measurement at " << Simulator::Now().GetSeconds() << "s");
    ResetOlsrCounters();
    
    // Create new FlowMonitor for defense phase
    FlowMonitorHelper flowHelper;
    g_defenseFlowMonitor = flowHelper.InstallAll();
    
    // Schedule end of defense measurement
    Simulator::Schedule(Seconds(MEASUREMENT_DURATION), &EndDefenseMeasurement, nodes);
}

static void EndAttackMeasurement(NodeContainer* nodes) {
    NS_LOG_INFO("Ending attack vs defense measurement at " << Simulator::Now().GetSeconds() << "s");
    
    FlowMonitorHelper flowHelper;
    SaveScenarioMetrics("defense_vs_attack", g_attackFlowMonitor, flowHelper, *nodes, 
                       ATTACK_MEASUREMENT_START, ATTACK_MEASUREMENT_END);
    
    // Clean up
    g_attackFlowMonitor = 0; // C++11 compatible null assignment
}

// PHASE 8: Attack vs Defense measurement functions
static void StartAttackMeasurement(NodeContainer* nodes) {
    NS_LOG_INFO("Starting attack vs defense measurement at " << Simulator::Now().GetSeconds() << "s");
    ResetOlsrCounters();
    
    // Create new FlowMonitor for attack phase
    FlowMonitorHelper flowHelper;
    g_attackFlowMonitor = flowHelper.InstallAll();
    
    // Schedule end of attack measurement
    Simulator::Schedule(Seconds(MEASUREMENT_DURATION), &EndAttackMeasurement, nodes);
}

// Enhanced connectivity check function
static void CheckAndReportConnectivity(NodeContainer* cont) {
    uint32_t fullyConnectedNodes = 0;
    for (uint32_t i = 0; i < cont->GetN(); ++i) {
        uint32_t routingTableSize = cont->Get(i)->GetObject<RoutingProtocol>()->getRoutingTableSize();
        if (routingTableSize == cont->GetN() - 1) {
            fullyConnectedNodes++;
        }
    }
    
    double connectivityRatio = (double)fullyConnectedNodes / cont->GetN();
    NS_LOG_INFO("Connectivity check: " << fullyConnectedNodes << "/" << cont->GetN() 
                << " nodes fully connected (" << (connectivityRatio * 100) << "%)");
    
    if (connectivityRatio < 0.8) { // 80% threshold
        NS_LOG_WARN("Poor connectivity detected! Ratio: " << connectivityRatio);
    }
}

// C++11 compatible logging functions (replace lambda functions)
static void LogDefenseActivation() {
    NS_LOG_INFO("Defense activation phase at " << Simulator::Now().GetSeconds() << "s");
}

static void LogAttackActivation() {
    NS_LOG_INFO("Attack activation phase at " << Simulator::Now().GetSeconds() << "s");
}

// Enhanced simulation statistics with ML dataset info
static void PrintSimStatsWithMLInfo(NodeContainer* cont) {
    std::cout << "@@   New Simulation   @@" << std::endl;
    std::cout << "Seed RngRun: " << RngSeedManager::GetRun() << std::endl;
    std::cout << "ML Dataset Run: " << g_currentRun << std::endl;
    std::cout << "Output Directory: " << g_outputBaseDir << std::endl;
    
    if (bIsolationAttackBug || bIsolationAttackNeighbor) {
        std::cout << "Attack: ON" << std::endl;
    } else {
        std::cout << "Attack: OFF" << std::endl;
    }
    
    if (bEnableFictive || bEnableFictiveMitigation) {
        std::cout << "Defence: ON" << std::endl;
    } else {
        std::cout << "Defence: OFF" << std::endl;
    }
    
    std::cout << "Phase Schedule:" << std::endl;
    std::cout << "- Phase 1 (0-60s): Network stabilization" << std::endl;
    std::cout << "- Phase 2 (61-80s): Baseline measurement" << std::endl;
    std::cout << "- Phase 3 (80s): Defense activation" << std::endl;
    std::cout << "- Phase 4 (80-140s): Defense stabilization" << std::endl;
    std::cout << "- Phase 5 (141-160s): Defense measurement" << std::endl;
    std::cout << "- Phase 6 (160s): Attack activation" << std::endl;
    std::cout << "- Phase 7 (160-220s): Attack/Defense interaction" << std::endl;
    std::cout << "- Phase 8 (221-240s): Attack vs Defense measurement" << std::endl;
}

/*
static void PrintTopologySet(NodeContainer* cont)
{
	ns3::iolsr::RoutingProtocol rp;
	for (unsigned int i=0;i<cont->GetN();i++)
	{
		Ptr<RoutingProtocol> pt = cont->Get(i)->GetObject<RoutingProtocol>();
		NS_LOG_INFO("Node id: "<<i<<"   "<<"Time: "<<Simulator::Now().GetSeconds());
		pt->PrintTopologySet();
	} 
}
*/
//alternative for cpp simulations:
int main2 (int argc, char *argv[]){

	//CPP version:
	if (__cplusplus == 201703L) std::cout << "C++17\n";
	    else if (__cplusplus == 201402L) std::cout << "C++14\n";
	    else if (__cplusplus == 201103L) std::cout << "C++11\n";
	    else if (__cplusplus == 199711L) std::cout << "C++98\n";
	    else std::cout << "pre-standard C++\n";


	return 0;
}

int main (int argc, char *argv[]){

	//CPP version:
	//if (__cplusplus == 201703L) std::cout << "C++17\n";
	//    else if (__cplusplus == 201402L) std::cout << "C++14\n";
	//    else if (__cplusplus == 201103L) std::cout << "C++11\n";
	//    else if (__cplusplus == 199711L) std::cout << "C++98\n";
	//    else std::cout << "pre-standard C++\n";

	// Time
	Time::SetResolution (Time::NS);
	
	// Variables
	uint32_t nNodes = 50; //Number of nodes in the simulation, default 50

	CreateOutputDirectories();

	//X,Y simulation rectangle - the range of movement of the nodes in the simulation
	double dMaxGridX = 750.0; //default 500x500
	uint32_t nMaxGridX = 750;
	double dMaxGridY = 1000.0;
	uint32_t nMaxGridY = 1000;

	bool bMobility = false; //Delcares whenever there is movement in the network
	uint32_t nProtocol = 0; //IOLSR=0, DSDV=1

	// Set running time
	double dSimulationSeconds = 240.0;
	uint32_t nSimulationSeconds = 240;
	//double dSimulationSeconds = 301.0;
	//uint32_t nSimulationSeconds = 301;

	std::string mProtocolName = "Invalid";
	bool bPrintSimStats = true; //simulation stats, such as random seed used, time.
	bool bSuperTransmission = false; //Transmission boost to node X?
	bool bPrintAll = false; //Print routing table for all hops
	bool bPrintFakeCount = true; //Print amount of fake nodes required
	bool bPrintMprFraction = true; //Print fraction of MPR
	bool bPrintRiskyFraction = true; //Print fraction of risky
	bool bIsolationAttack = false; //Execute isolation attack by a node
	bIsolationAttackBug = false; //Have an attacker stick to it's target  *****
	bIsolationAttackNeighbor = true; //Execute isolation attack by a random neighbor
	bEnableFictive = false; //Activate fictive defence mode   *****
	bEnableFictiveMitigation = true; //Activate new fictive defence mode (new algorithm, mitigation)
	bool bHighRange = false; //Higher wifi range. 250m should suffice. txGain at 12.4
	bool bPrintTcPowerLevel = true; //Print average TC size
	bool bNeighborDump = false; //Neighbor dump
	bool bIsolationAttackMassive = false; //Execute isolation attack by many nodes
	bool bConnectivityPrecentage = true; //Print connectivity precetage every X seconds
	bool bUdpServer = true; //Try to send UDP packets from node1 to node0
	bool bAssertConnectivity = false; //Stop simulation if network is not fully connected, at certain time.
	bool printTotalMprs = true; //prints the MPR sub-network total MPRs, and addresses of MPRs.
	bool printDetectionInC6 = true;
	bool print2hop = true;
	bool printNodesDeclaringFictive = true;
	uint32_t printNodeOutputLog = 999; // 999 to disable this function, otherwise supply node ID.
	uint32_t assertConnectivityAtTime = 160; //The time for simulation termination if network is not fully connected.
	// uint32_t startAttackTime = 150; //The time for an attacker to start attacking.
	// uint32_t startDefenceTime = 60; //The time for defense to start.
	// uint32_t startUdpSend = 250; //The time to start sending messages to victim. total 18 msgs. 4sec intervals. 72seconds to complete.
	// uint32_t reportStatsAtTime = 295; //The time for simulation to report statistics and data to cout << .
	uint32_t startDefenceTime = 80;     // Defense activation
	uint32_t startAttackTime = 160;     // Attack activation
	uint32_t startUdpSend = 200;        // UDP traffic (optional, during attack phase)
	uint32_t reportStatsAtTime = 235;   // Final stats reporting


	// Parameters from command line
	CommandLine cmd;
	cmd.AddValue("nNodes", "Number of nodes in the simulation", nNodes);
	cmd.AddValue("nMaxGridX", "X of the simulation rectangle", nMaxGridX);
	cmd.AddValue("nMaxGridY", "Y of the simulation rectangle", nMaxGridY);
	cmd.AddValue("bMobility", "Delcares whenever there is movement in the network", bMobility);
	cmd.AddValue("nProtocol", "IOLSR=0, DSDV=1", nProtocol);
	cmd.AddValue("nSimulationSeconds", "Amount of seconds to run the simulation", nSimulationSeconds);
	cmd.AddValue("bSuperTransmission", "Transmission boost to node X?", bSuperTransmission);
	cmd.AddValue("bPrintAll", "Print routing table for all hops", bPrintAll);
	cmd.AddValue("bPrintFakeCount", "Print amount of fake nodes required", bPrintFakeCount);
	cmd.AddValue("bPrintMprFraction", "Print fraction of MPR", bPrintMprFraction);
	cmd.AddValue("bPrintRiskyFraction", "Print fraction of risky", bPrintRiskyFraction);
	cmd.AddValue("bPrintTcPowerLevel", "Print average TC size", bPrintTcPowerLevel);
	cmd.AddValue("bIsolationAttack", "Execute isolation attack by a node", bIsolationAttack);
	cmd.AddValue("bIsolationAttackNeighbor", "Execute isolation attack by a random neighbor", bIsolationAttackNeighbor);
	cmd.AddValue("bIsolationAttackMassive", "Execute isolation attack by many nodes", bIsolationAttackMassive);
	cmd.AddValue("bEnableFictive", "Activate fictive defence mode", bEnableFictive);
	cmd.AddValue("bEnableFictiveMitigation", "Activate new fictive defence mode (new algorithm, mitigation)", bEnableFictive);
	cmd.AddValue("bHighRange", "Higher wifi range", bHighRange);
	cmd.AddValue("bNeighborDump", "Neighbor dump", bNeighborDump);
	cmd.AddValue("bConnectivityPrecentage", "Print connectivity precetage every X seconds", bConnectivityPrecentage);
	cmd.AddValue("bIsolationAttackBug", "Have an attacker stick to it's target", bIsolationAttackBug);
	cmd.AddValue("bUdpServer", "Try to send UDP packets from node1 to node0", bUdpServer);
	cmd.AddValue("run", "Run number for output files", g_currentRun);
	cmd.AddValue("outputDir", "Base output directory", g_outputBaseDir);
	cmd.Parse (argc, argv);

	if (nSimulationSeconds > 10.0) dSimulationSeconds = nSimulationSeconds; // Force minimum time
	if (nMaxGridX > 10.0) dMaxGridX = nMaxGridX; // Force minimum size. Revert to default.
	if (nMaxGridY > 10.0) dMaxGridY = nMaxGridY; // Force minimum size. Revert to default.

	// Build network
	NodeContainer nodes;
	nodes.Create (nNodes);
		
	// Add wifi
	WifiHelper wifi;
	//wifi.SetStandard(WIFI_PHY_STANDARD_80211g);
	YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
	YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
	NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
	if (bHighRange){
		wifiPhy.Set("TxGain", DoubleValue(12.4));
		wifiChannel.AddPropagationLoss ("ns3::RangePropagationLossModel", "MaxRange", DoubleValue (250));
	} else {
		wifiPhy.Set("TxGain", DoubleValue(12.4));
		wifiChannel.AddPropagationLoss ("ns3::RangePropagationLossModel", "MaxRange", DoubleValue (190));
	}
	wifiPhy.SetChannel(wifiChannel.Create());
	wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager");
	wifiMac.SetType ("ns3::AdhocWifiMac");
	//wifiChannel.AddPropagationLoss ("ns3::RangePropagationLossModel", "MaxRange", DoubleValue (105));
	NetDeviceContainer adhocDevices = wifi.Install (wifiPhy, wifiMac, nodes);

	// Rig Node for huge wifi boost
	if (bSuperTransmission){
		NodeContainer superNodes;
		superNodes.Create (1);
		wifiPhy.Set("RxGain", DoubleValue(500.0));
		wifiPhy.Set("TxGain", DoubleValue(500.0));
		NetDeviceContainer superDevices = wifi.Install (wifiPhy, wifiMac, superNodes);
		adhocDevices.Add(superDevices);
		nodes.Add(superNodes);
	}

	// Install IOLSR / DSDV
	IOlsrHelper iolsr;
	DsdvHelper dsdv;
	Ipv4ListRoutingHelper routeList;
	InternetStackHelper internet;
	std::stringstream tmpStringStream;
	std::string fName = "Stable_Network_Stream";
	fName += "_n";
	tmpStringStream << nNodes;
	fName += tmpStringStream.str();
	tmpStringStream.str("");
	fName += "_x";
	tmpStringStream << nMaxGridX;
	fName += tmpStringStream.str();
	tmpStringStream.str("");
	fName += "_y";
	tmpStringStream << nMaxGridY;
	fName += tmpStringStream.str();
	tmpStringStream.str("");
	fName += "_r";
	tmpStringStream << RngSeedManager::GetRun();
	fName += tmpStringStream.str();
	tmpStringStream.str("");
	fName += ".txt";
	//Ptr<OutputStreamWrapper> stream = Create<OutputStreamWrapper>("Stable_Network_Stream_Run",std::ios::out);	
	//Ptr<OutputStreamWrapper> stream = Create<OutputStreamWrapper>(fName,std::ios::out);	

	switch (nProtocol){
		case 0:
			routeList.Add (iolsr, 100);
			if (!bPrintAll){
				//iolsr.PrintRoutingTableEvery(Seconds(10.0), nodes.Get(1), stream);
			} else {
				Ptr<OutputStreamWrapper> stream = Create<OutputStreamWrapper>(fName,std::ios::out);	
				iolsr.PrintRoutingTableAllEvery(Seconds(10.0), stream);
			}
			break;
		case 1:
			routeList.Add (dsdv, 100);
			if (!bPrintAll) {
				//dsdv.PrintRoutingTableEvery(Seconds(10.0), nodes.Get(1), stream);
			} else {
				Ptr<OutputStreamWrapper> stream = Create<OutputStreamWrapper>(fName,std::ios::out);	
				dsdv.PrintRoutingTableAllEvery(Seconds(10.0), stream);
			}
			break;
		default:
			NS_FATAL_ERROR ("Invalid routing protocol chosen " << nProtocol);
			break;
	}
	internet.SetRoutingHelper(routeList);
	internet.Install (nodes);

	// Install IP
	Ipv4AddressHelper addresses;
	addresses.SetBase ("10.0.0.0", "255.0.0.0");
	Ipv4InterfaceContainer interfaces;
	interfaces = addresses.Assign (adhocDevices);

	// Install mobility
	MobilityHelper mobility;
	Ptr<UniformRandomVariable> randomGridX = CreateObject<UniformRandomVariable> ();
	Ptr<UniformRandomVariable> randomGridY = CreateObject<UniformRandomVariable> ();
	randomGridX->SetAttribute ("Min", DoubleValue (0));
	randomGridX->SetAttribute ("Max", DoubleValue (dMaxGridX));
	randomGridY->SetAttribute ("Min", DoubleValue (0));
	randomGridY->SetAttribute ("Max", DoubleValue (dMaxGridY));

	Ptr<RandomRectanglePositionAllocator> taPositionAlloc = CreateObject<RandomRectanglePositionAllocator> ();
	taPositionAlloc->SetX(randomGridX);
	taPositionAlloc->SetY(randomGridY);
	mobility.SetPositionAllocator (taPositionAlloc);
	if (bMobility) {
		mobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
				"Bounds", RectangleValue (Rectangle (0, dMaxGridX, 0, dMaxGridY)),
				//"Speed", StringValue("ns3::UniformRandomVariable[Min=0|Max=2.0]"),
				"Speed", StringValue("ns3::UniformRandomVariable[Min=1.5|Max=2.0]"),
				//"Speed", StringValue("ns3::UniformRandomVariable[Min=9.5|Max=10.0]"),
				"Time", TimeValue(Seconds(3.0)),
				"Mode", EnumValue(RandomWalk2dMobilityModel::MODE_TIME));
	} else {
		mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
	}
	mobility.Install (nodes);


	if (bUdpServer){
		UdpServerHelper udpServerHelper(80);
		ApplicationContainer apps = udpServerHelper.Install(nodes.Get(0));
		Ptr<UdpServer> udpServer = udpServerHelper.GetServer();
		UdpClientHelper udpClientHelper(Ipv4Address("10.0.0.1"), 80);
		udpClientHelper.SetAttribute("Interval", TimeValue(Seconds(2))); //The time to wait between packets
		udpClientHelper.SetAttribute("MaxPackets", UintegerValue(18)); //The maximum number of packets the application will send
		udpClientHelper.SetAttribute("PacketSize", UintegerValue(512));

		
		// Choose random node to become sender
		//Ptr<UniformRandomVariable> rnd = CreateObject<UniformRandomVariable> ();
		//rnd->SetAttribute ("Min", DoubleValue (3));
		//rnd->SetAttribute ("Max", DoubleValue (nodes.GetN()-1));
		

		// Install UdpClient on said node
		//uint32_t sendingNode = rnd->GetInteger();
		uint32_t sendingNode = 1;
		apps.Add(udpClientHelper.Install(nodes.Get(sendingNode)));
		//apps.Add(udpClientHelper.Install(nodes.Get(1)));
		apps.Start(Seconds(startUdpSend)); 
		apps.Stop(Seconds(nSimulationSeconds)); //at the end of simulation
//		if (false){
//			for (size_t i=30; i<nSimulationSeconds-5; i=i+1){
		Simulator::Schedule(Seconds (startUdpSend-2), &AbortOnNeighbor, nodes.Get(sendingNode), Ipv4Address("10.0.0.1"));
//			}
//		}
		Simulator::Schedule(Seconds (nSimulationSeconds+2), &AbortIfNotReceivedPackets, udpServer); //(currently, never)
		Simulator::Schedule(Seconds (reportStatsAtTime+0.01), &ReportNumReceivedPackets, udpServer);
	}


	if (bPrintSimStats) {
	    Simulator::Schedule(Seconds(5), &PrintSimStatsWithMLInfo, &nodes);
	}
	
	if(printDetectionInC6){
		Simulator::Schedule(Seconds (reportStatsAtTime+0.02), &PrintC6Detection, &nodes);
	}

	if (bPrintFakeCount) {
	// Execute PrintCountFakeNodes after the delay time
		//Ptr<OutputStreamWrapper> wrap = Create<OutputStreamWrapper>("StableNetwork-Mod-FakeNodes.txt", ios::out);
		Simulator::Schedule(Seconds (reportStatsAtTime), &PrintCountFakeNodes, &nodes);
		//Simulator::Schedule(Seconds (240), &PrintCountFakeNodes, &nodes);
	}

	if(printNodeOutputLog != 999){
		Simulator::Schedule(Seconds (reportStatsAtTime+0.3), &PrintNodeOutputLog, &nodes, printNodeOutputLog);
	}

	if (printNodesDeclaringFictive) {
	// Execute PrintCountFakeNodes after the delay time
		//Ptr<OutputStreamWrapper> wrap = Create<OutputStreamWrapper>("StableNetwork-Mod-FakeNodes.txt", ios::out);
		Simulator::Schedule(Seconds (reportStatsAtTime), &PrintNodesDeclaredFictive, &nodes);
		//Simulator::Schedule(Seconds (240), &PrintCountFakeNodes, &nodes);
	}

	if (bPrintMprFraction) {
	// Execute PrintMprFraction after the delay time 
		Simulator::Schedule(Seconds (reportStatsAtTime), &PrintMprFraction, &nodes);
		//Simulator::Schedule(Seconds (240), &PrintMprFraction, &nodes);
	}

	if(printTotalMprs){
		Simulator::Schedule(Seconds (reportStatsAtTime), &PrintMprs, &nodes);

	}

	if(print2hop){
		Simulator::Schedule(Seconds (reportStatsAtTime), &Print2hopNeighborsOfVictim, &nodes);
	}

	if (bPrintRiskyFraction) {
	// Execute PrintMprFraction after the delay time 
		Ipv4Address ignore = Ipv4Address("0.0.0.0");
		if (bIsolationAttackBug) ignore = Ipv4Address("10.0.0.3"); //If an attacker stick to it's target then we ignore 10.0.0.3
		Simulator::Schedule(Seconds (reportStatsAtTime), &PrintRiskyFraction, &nodes, ignore);
		//Simulator::Schedule(Seconds (240), &PrintRiskyFraction, &nodes, ignore);
	}
	if (bPrintTcPowerLevel) {
	// If bPrintTcPowerLevel -> Print average TC size
		Simulator::Schedule(Seconds (reportStatsAtTime), &PrintTcPowerLevel, &nodes);
		//Simulator::Schedule(Seconds (240), &PrintTcPowerLevel, &nodes);
	}
	if (bIsolationAttack){
	// If bIsolationAttack -> Execute isolation attack by a node
		Simulator::Schedule(Seconds (startAttackTime), &ExecuteIsolationAttack, &nodes);
	}
	if (bIsolationAttackMassive){
	// If bIsolationAttackMassive -> Execute isolation attack by many nodes
		Simulator::Schedule(Seconds (startAttackTime), &ExecuteIsolationAttackMassive, &nodes);
	}
	if (bIsolationAttackBug){
		// If bIsolationAttackBug -> Have an attacker stick to it's target

		
		Vector vec = nodes.Get(0)->GetObject<MobilityModel>()->GetPosition();
		vec.x += 8;
		vec.y += 0;
		nodes.Get(2)->GetObject<MobilityModel>()->SetPosition(vec);
		//DynamicCast<YansWifiPhy>(DynamicCast<WifiNetDevice>(nodes.Get(2)->GetDevice(0))->GetPhy())->SetTxGain(1.2);

		for (size_t i=1; i<nSimulationSeconds; ++i){
			Simulator::Schedule(Seconds (i), &TrackTarget, nodes.Get(0), nodes.Get(2));
			if(i == startAttackTime){
				nodes.Get(2)->GetObject<RoutingProtocol>()->ExecuteIsolationAttack(Ipv4Address("10.0.0.1"));
			}
		}
	}
	if (bIsolationAttackNeighbor){
		// If bIsolationAttackNeighbor -> Execute isolation attack by a random neighbor
			Simulator::Schedule(Seconds (startAttackTime), &ExecuteIsolationAttackByNeighbor, &nodes, Ipv4Address("10.0.0.1"));
	}
	if (bEnableFictive){
		// If bEnableFictive -> Activate fictive defence mode
		//Simulator::Schedule(Seconds (0), &ActivateFictiveDefence, &nodes);
		Simulator::Schedule(Seconds (startDefenceTime), &ActivateFictiveDefence, &nodes);
	}
	if (bEnableFictiveMitigation){ //new algo
		// If bEnableFictiveMitigation -> Activate new fictive defence mode (new algorithm, mitigation)
		//Simulator::Schedule(Seconds (0), &ActivateFictiveMitigation, &nodes);
		Simulator::Schedule(Seconds (startDefenceTime), &ActivateFictiveMitigation, &nodes);
	}
	if (bNeighborDump){
		/* IneffectiveNeighorWrite create two txt files
		   _mpr.txt - for each node a list of it's MPRs  
		   _neighbor.txt - for each node node a list of it's 1-hop neighbors and their address 
		   */
		Simulator::Schedule(Seconds (reportStatsAtTime), &IneffectiveNeighorWrite, &nodes);
	}
	
	if (bAssertConnectivity){
		// If bAssertConnectivity -> 

		// Assert connectivity
		Simulator::Schedule(Seconds (assertConnectivityAtTime), &AssertConnectivity, &nodes); 
	}
	if (bConnectivityPrecentage){
	// If bConnectivityPrecentage -> Print connectivity precetage every X seconds
		Simulator::Schedule(Seconds (reportStatsAtTime+0.02), &PercentageWithFullConnectivity, &nodes);
	}
	if (false){
		Simulator::Schedule(Seconds (reportStatsAtTime), &PrintTables, nodes.Get(0), std::string("V")); //default 251, for all 3.
		Simulator::Schedule(Seconds (reportStatsAtTime), &PrintTables, nodes.Get(2), std::string("A"));
		Simulator::Schedule(Seconds (reportStatsAtTime), &IneffectiveNeighorWrite, &nodes);
	}

	// Print Topology Set
	//Simulator::Schedule(Seconds (35) , &PrintTopologySet, &nodes);

	// Schedule connectivity check before baseline
	Simulator::Schedule(Seconds(58.0), &CheckAndReportConnectivity, &nodes);
	
	// Schedule Phase 2: Baseline measurement (61-80s)
	Simulator::Schedule(Seconds(BASELINE_START), &StartBaselineMeasurement, &nodes);
	
	// Schedule Phase 5: Defense measurement (141-160s)
	Simulator::Schedule(Seconds(DEFENSE_MEASUREMENT_START), &StartDefenseMeasurement, &nodes);
	
	// Schedule Phase 8: Attack vs Defense measurement (221-240s)
	Simulator::Schedule(Seconds(ATTACK_MEASUREMENT_START), &StartAttackMeasurement, &nodes);
	
	// Add logging for existing defense activation
	if (bEnableFictiveMitigation) {
	    Simulator::Schedule(Seconds(DEFENSE_ACTIVATION), &LogDefenseActivation);
	}
	
	// Add logging for existing attack activation
	if (bIsolationAttackNeighbor) {
	    Simulator::Schedule(Seconds(ATTACK_ACTIVATION), &LogAttackActivation);
	}
	
	// Animation
	AnimationInterface anim ("Stable_Network_animation.xml");
	anim.SetMobilityPollInterval (Seconds (1));

	// Pcap
	wifiPhy.EnablePcap("DelayTest_", NodeContainer(nodes.Get(0)));
	wifiPhy.EnablePcap("DelayTest_", NodeContainer(nodes.Get(1)));
	//wifiPhy.EnablePcap("DelayTest_", nodes.Get(1));
	//wifiPhy.EnablePcapAll ("DelayTest_");
	//std::ostringstream sspcap;
	//sspcap << "BottleNeck_" << "FixPos_" << bFixPos << "_";
	//wifiPhy.EnablePcapAll (sspcap.str());

	// Ptr<FlowMonitor> flowMon;
	// FlowMonitorHelper flowHelper;
	// flowMon = flowHelper.InstallAll();

	Config::Connect("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacTx", MakeCallback(&MacTxCallback));
	Config::Connect("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacTxDrop", MakeCallback(&MacTxControlCallback));

	for (uint32_t i = 0; i < nodes.GetN (); ++i)
  	{
    	Ptr<Ipv4> ipv4 = nodes.Get (i)->GetObject<Ipv4> ();
    	ipv4->TraceConnectWithoutContext ("Tx", MakeCallback (&TraceOlsrPacket));
  	}
	
	// Run simulation
	NS_LOG_INFO ("Run simulation.");
	Simulator::Stop (Seconds (dSimulationSeconds));

	Simulator::Run ();

	//RngSeedManager::GetRun()
	std::ostringstream oss;
	oss << "./simulations/features/att-1_def-1/metrics_output-" << RngSeedManager::GetRun() << ".csv";

	// ExtractAndLogMetrics(flowMon, flowHelper, nodes, oss.str().c_str());

	Simulator::Destroy ();

	return 0;
}
