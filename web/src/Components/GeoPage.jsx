import { useEffect, useState } from "react"
import SideBar from "./SideBar"
import { AiOutlineGlobal } from "react-icons/ai";
import Error from "./Error";
import IPDetails from "./IPDetails";
import "./GeoPage.css"
import Loading from "./Loading";
function GeoPage(){
    const [loading,setLoading] = useState(false)
    const [selectedIP, setSelectedIP] = useState("none")
    const [location,setLocation] = useState(null)
    const [data,setData] = useState([])
    const [file, setFile] = useState(null);
    const [error,setError] = useState(false)

    useEffect(()=>{
        if(selectedIP !== "none"){
            setLoading(true)
            //make the API request
            fetch('https://ipapi.co/json/') // or 'https://ipinfo.io/json?token=YOUR_TOKEN'
        .then(res => res.json())
        .then(data => {
            console.log(data)
            setLocation(data);
            setLoading(false)
        });
        }
    },[selectedIP])
    
    function handleSelect(event){
        //Func:
        //Args:
        //Docs: This function will be called when a IP address is selcted
        console.log(event.target.value)
        setSelectedIP(event.target.value)
    }
    function uploadFile(){
        setLoading(true)
        const formData = new FormData();
        formData.append('file', file);
        
        fetch('http://localhost:8000/list/ips', {
        method: 'POST',
        headers: {
            accept: 'application/json',
        },
        body: formData,
        })
        .then(res => {
            if(res.ok){
                return res.json()
            }else{
                setError(true)
            }
        })
        .then(d =>{
            setData(d)
            console.log('Upload success:', d)
            setLoading(false)
        } )
        .catch(err => {
            setError(true)
            setLoading(false)
        });

    }
    function display(){
        return <>
            <h1>Select IP address to get Geo-location</h1>
            <select for="protocols" id="protocols" value={null} onChange={(e) => handleSelect(e)}>
                <option value="All">All</option>
                {data["data"].map(item => <option key={item} value={item}>IP: {item}</option>)}

            </select>
        </>
    }
    function displayUpload(){
        //Func: displayUpload
        //Args:
        //Docs: This function will display the upload file section
        return <>
        <h1>Get Geo-Location of IP's <AiOutlineGlobal size={40} /></h1>
        <input type="file" accept=".pcap" onChange={(e) => setFile(e.target.files[0])} />
        <button onClick={()=> uploadFile()} disabled={!file}>Upload</button>
        </>
    }
    function main(){
        if(error === true){
            return <Error setError={setError} setLoading={setLoading}/>
        }
        if(data.length === 0){
            return <>{displayUpload()}</>

        }else{
            return <> { display()}</>
        }
    }

    return <div className="geo-container">
    <SideBar/>
    {main()}
    {loading && <Loading txt={"Please wait, analyse file...."}/>}
    {location !== null &&  <IPDetails ip={selectedIP} data={location}/>}

    </div>
}
export default GeoPage