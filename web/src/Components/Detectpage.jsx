import SideBar from "./SideBar"
import { useState } from "react"
import "./Home.css"
import "./Detectpage.css"
import FloodResults from "./FloodResults"
import Error from "./Error"
function Detectpage(){
    const [data,setData] = useState([])
    const [file, setFile] = useState(null);
    const [loading,setLoading] = useState(false)
    const [error, setError] = useState(false)

    const handleUpload = () => {
        setLoading(true)
        const formData = new FormData();
        formData.append('file', file);
        //http://localhost:8000/test124
        fetch('http://localhost:8000/upload/detect-ddos', {
            method: 'POST',
            headers: {
                accept: 'application/json',
            },
            body: formData,
            })
            .then(res => res.json())
            .then(d =>{
                setData(d.data)
                console.log('Upload success:', d)
                setLoading(false)
            } )
            .catch(err => setError(true));
    }
    function Display(){
        if(error === true){
            return <Error setError={setError} setLoading={setLoading}/>

        }
        if(loading === true){
            return <div> 
            <div className="spinner"></div>
            <p>Please wait while we analyze the file....</p>
        </div>

        }
        if(data.length === 0){
            return <>
            <h1 style={{"marginBottom":"0px"}}>Upload pcap file to analyze for DDoS attacks</h1>
            <h4 style={{"marginTop":"0px"}}>This program will detect: SYN flood, UDP flood and ICMP flood</h4>
            <input type="file" accept=".pcap" onChange={(e) => setFile(e.target.files[0])} />
            <button onClick={ handleUpload} disabled={!file}>Upload</button>
                </>
        }
        // Display results from server
        return <div>
            <h1>Flood details</h1>
            <FloodResults data={data[0]} title={"SYN Flood results"}/>
            <FloodResults data={data[1]} title={"UDP Flood results"}/>
            <FloodResults data={data[2]} title={"ICMP Flood results"}/>
            
        </div>
    }
   
    return <>
        <SideBar/>
        {Display()}
    </>
}
export default Detectpage