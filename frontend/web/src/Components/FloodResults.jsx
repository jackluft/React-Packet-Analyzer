import { useState } from "react"
import "./FloodResults.css"
function FloodResults({title,data}){
    const [expand,setExpand] = useState(false)
    const tempStyle = {
        "borderBottomRightRadius": "0px",
        "borderBottomLeftRadius": "0px"
    }
    if(data["FLOOD DETECTED"] === true){
        console.log(data["packets"])
    }
    function roundToTwo(num) {
        return Math.round(num * 100) / 100;
      }
    function displayAttackDetails(){
        //Func:
        //Args:
        //Docs: This function will display the details of the attack
        const avg_rate = roundToTwo(data["avg packet rate"])
        const attack_dur = roundToTwo(data["Attack Duration"])
        return <div>
            <p className="attack-details">Avg packet rate: {avg_rate}/Secs</p>
            <p className="attack-details">Attack Duration: {attack_dur}/Secs</p>
        </div>
    }
    function ddos_data(){
        //Func: ddos_data
        //Args: None
        //Docs: This function will display all the details of the DDoS attack detected
        const ip_list = data["packets"]
        return <div>
            <h1 style={{"marginTop":"0px"}}>DDoS attack has been detected</h1>
            <h1>Below is a list of IP address suspected to be the course of the attack</h1>
            {displayAttackDetails()}
            <div className="ip-list-container">
            <table className="content-table">
                <thead>
                    <tr>
                    <th style={{"width":"200px"}}>IP source:</th>
                    <th style={{"width":"200px"}}>Target IP:</th>
                    <th style={{"width":"200px"}}>Number of packets sent</th>
                    </tr>

                </thead>
                <tbody>

                
                    {ip_list.map(obj=> <>
                    
                            <tr>
                                <td>{obj["packet"]["src_IP"]}</td>
                                <td>{obj["packet"]["dst_IP"]}</td>
                                <td>{obj["count"]}</td>
                            </tr>
                        
                        
                        
                        </> )}
                </tbody>
                </table>



            </div>

        </div>
        

    }
    return <div className="flood-container">
        <div style={ expand ? tempStyle: {}} className="flood-title-container">
            <h1 className="flood-text">{title}</h1>
            <button onClick={() => setExpand(!expand)} className="expand-btn">+</button>
        </div>

        {expand && <div className="results-display">
            {data["FLOOD DETECTED"] === false ? <h1 style={{"marginTop":"0px"}}>No DDoS attack has been detected</h1> : ddos_data() }
            </div>}

    </div>
    

}

export default FloodResults