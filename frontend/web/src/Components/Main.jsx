import {useState } from "react"
import PacketComponent from "./PacketComponent";
import SideBar from "./SideBar";
import "./Home.css"

function Main(){
    const [file, setFile] = useState(null);
    const [data,setData] = useState([])
    const [loading,setLoading] = useState(false)
    const handleUpload = () => {
        setLoading(true)
        const formData = new FormData();
        formData.append('file', file);
        
        fetch('http://localhost:8000/upload/pcap', {
        method: 'POST',
        headers: {
            accept: 'application/json',
        },
        body: formData,
        })
        .then(res => res.json())
        .then(d =>{
            setData(d)
            console.log('Upload success:', d)
            setLoading(false)
        } )
        .catch(err => console.error('Upload error:', err));
    };
  function uploadFile(){
    if(loading === true){
        {console.log("Spinning!!!")}
        return <div> 
            <div className="spinner"></div>
            <p>Please wait while we analyze the file....</p>
        </div>
        

    }
    if(data.length === 0){
        return <>
        <input type="file" accept=".pcap" onChange={(e) => setFile(e.target.files[0])} />
        <button onClick={ handleUpload} disabled={!file}>Upload</button>
    </>
    }else{
        return <PacketComponent packets={data}/>
    }
    
  }

  return (
    <div>
        <SideBar/>
      
    {uploadFile()}
    
    </div>
  );


}
export default Main