import Packet from "./Packet"
import { useState } from "react"
import "./PacketComponent.css"
function PacketComponent({packets}){
    const [selectedProtocol, setSelectedProtocol] = useState('All');
    const [multi,setMulti] = useState([])
    if (!packets || !packets.data) {
        return <div>Loading packets...</div>;  // or just return nothing
      }
      //console.log(packets["data"])
      const protocolColors = {
        'HTTP': '#FFD700',
        'HTTPS': '#228B22',
        'TCP': '#87CEFA',
        'UDP': '#9370DB',
        'DNS': '#FFA500',
        'ARP': '#FF7F7F',
        'ICMP': '#40E0D0',
        'SSH': '#8B0000',
        'FTP': '#90EE90',
        'SMTP': '#F08080',
        'DHCP': '#FFB347',
        'TLS': '#4169E1',
        'SNMP': '#EE82EE',
        'RDP': '#6A5ACD',
        'MDNS': '#BA55D3',
        'QUIC': '#32CD32',
        'other':"gray"
      };
    const total_packets = packets.data[0]["size"]
    const dns_packet_size = packets.data[0]["DNS-Size"]
    const quic_packet_size = packets.data[0]["QUIC-Size"]
    const mdns_packet_size = packets.data[0]["MDNS-Size"]
    const arp_packet_size = packets.data[0]["ARP-Size"]
    const http_packet_size = packets.data[0]["HTTP-Size"]
    const tcp_packet_size = packets.data[0]["TCP-Size"]
    const icmp_packet_size = packets.data[0]["ICMP-Size"]
    const udp_packet_size = packets.data[0]["UDP-Size"]
    const other_packet_size = packets.data[0]["OTHER-Size"]

    const all_packets = packets.data[1]["Packets"]
    function hangleChange(event){
        setSelectedProtocol(event.target.value);
    }
    function packetClick(id){
        console.log("Packet: "+id)
        let mulCpy = [...multi]
        const findIndex = mulCpy.indexOf(id)
        if(findIndex === -1){
            mulCpy.push(id)

        }else{
            mulCpy.splice(findIndex,1)
        }
        setMulti(mulCpy)
    }
    return <div className="all-packet-info">
        
        <div className="display-packet-info">
            {/* <h3 className="packet-type-text">Packet type: </h3> */}
            <div className="display-protocol-type-section">
            <h1 className="total-packet-text">Total packets: {total_packets}</h1>
                {dns_packet_size > 0 ? <p className="protocol-type-display" style={{"backgroundColor":protocolColors["DNS"]}}>DNS: {dns_packet_size}</p>: null}
                {quic_packet_size > 0 ? <p className="protocol-type-display" style={{"backgroundColor":protocolColors["QUIC"]}}>QUIC: {quic_packet_size}</p>: null}
                {mdns_packet_size > 0 ? <p className="protocol-type-display" style={{"backgroundColor":protocolColors["MDNS"]}}>MDNS: {mdns_packet_size}</p>: null}
                {arp_packet_size > 0 ? <p className="protocol-type-display" style={{"backgroundColor":protocolColors["ARP"]}}>ARP: {arp_packet_size}</p>: null}
                {http_packet_size > 0 ? <p className="protocol-type-display" style={{"backgroundColor":protocolColors["HTTP"]}}>HTTP: {http_packet_size}</p>: null}
                {tcp_packet_size > 0 ? <p className="protocol-type-display" style={{"backgroundColor":protocolColors["TCP"]}}>TCP: {tcp_packet_size}</p>: null}
                {icmp_packet_size > 0 ? <p className="protocol-type-display" style={{"backgroundColor":protocolColors["ICMP"]}}>ICMP: {icmp_packet_size}</p>: null}
                {udp_packet_size > 0 ? <p className="protocol-type-display" style={{"backgroundColor":protocolColors["UDP"]}}>UDP: {udp_packet_size}</p>: null}
                {other_packet_size > 0 ? <p className="protocol-type-display" style={{"backgroundColor":protocolColors["other"]}}>Other: {other_packet_size}</p>: null}
                <label htmlFor="protocols">Filter Protocols: </label>
            <select for="protocols" id="protocols" value={selectedProtocol} onChange={hangleChange}>
                <option value="All">All</option>
                {dns_packet_size > 0 && <option value="DNS">DNS</option>}
                {quic_packet_size > 0 && <option value="QUIC">QUIC</option>}
                {mdns_packet_size > 0 && <option value="MDNS">MDNS</option>}
                {arp_packet_size > 0 && <option value="ARP">ARP</option>}
                {http_packet_size > 0 && <option value="HTTP">HTTP</option>}
                {tcp_packet_size > 0 && <option value="TCP">TCP</option>}
                {icmp_packet_size > 0 && <option value="ICMP">ICMP</option>}
                {udp_packet_size > 0 && <option value="ICMP">UDP</option>}
                {other_packet_size > 0 && <option value="other">Other</option>}

            </select>
            </div>
           
            
        </div>
        <div className="packet-list">
            {all_packets.map((item,id) => {
                if(selectedProtocol === "All"){
                    return <Packet click={packetClick} show={multi.indexOf(id) !== -1 ? true : false}  id={id} key={id} packet={item} color={protocolColors[item.protocol]} />
                }else if(item.protocol === selectedProtocol){
                return  <Packet click={packetClick} show={multi.indexOf(id) !== -1 ? true : false}  id={id} key={id} packet={item} color={protocolColors[item.protocol]} />
                }
                
            }
            )}
        </div>
        
        
        
    </div>

}
export default PacketComponent