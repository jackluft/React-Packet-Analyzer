import "./Packet.css"
function Packet({packet,color,click, id,show}){

    const ClickedStyle = {"borderTopLeftRadius": "12px","borderTopRightRadius": "12px","borderBottomRightRadius": "0px","borderBottomLeftRadius": "0px"}
    function displayPacketContent(){
        if(packet.protocol === "TCP" || packet.protocol === "QUIC"){
            //Extract TCP data content
            let src_port = packet["packet_content"]["src_port"]
            let dst_port = packet["packet_content"]["dst_port"]
            return <div className="packet-details">
                <div className="tcp-port-content">
                <p className="port-display">Src Port: {src_port}</p>
                <p className="port-display">Dst Port: {dst_port}</p>
                </div>
                <div className="tcp-mac-content">
                    <p className="mac-display">MAC src: {packet["src_mac"]}</p>
                    <p className="mac-display">MAC dst: {packet["dst_mac"]}</p>
                </div>
                {packet.protocol === "TCP" && <div className="tcp-time-flags">
                    <p style={{"marginTop":"0px","marginBottom":"0px"}}>Flags: {packet["packet_content"]["flags"]}</p>
                    <p style={{"marginTop":"0px","marginBottom":"0px"}}>Packet time: {packet["time"]}</p>
                </div>
                }
                
                
            
            </div>

        }
        return <div className="packet-details">Extract details about the packet</div>

    }
    return <div className="main-packet-container">
        <div onClick={() => click(id)} className="packet-container" style={show ? ClickedStyle: null}>
            <span className="protocol-color" style={{"backgroundColor": color}}>&nbsp;</span>
            { packet.protocol !== "ARP" ? <h1 className="ip-src">IP src: {packet["src_IP"]}</h1>: <h1 className="mac-src">MAC src: {packet["src_mac"]}</h1>}
            {packet.protocol !== "ARP" ? <h1 className="ip-dst"> IP dst: {packet["dst_IP"]}</h1>: <h1 className="mac-dst">MAC dst: {packet["dst_mac"]}</h1>}
            <h1 className="packet-size">Packet size: {packet["Packet_size"]} bytes</h1>
            {packet["payload_size"] !== undefined ? <h1 className="payload-size">Payload size: {packet["payload_size"]} bytes</h1> : <h1 className="payload-size">Payload size: None bytes</h1>}
            
    </div>
    {
        show && displayPacketContent()
    } 

    </div>
     

}
export default Packet