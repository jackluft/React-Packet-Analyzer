import "./sidebar.css"
import { GiVirus } from "react-icons/gi";
import { LiaNetworkWiredSolid } from "react-icons/lia";
import { IoMdGlobe } from "react-icons/io";
import { FaHome } from "react-icons/fa";
import { useNavigate } from 'react-router-dom';
function SideBar(){
    const navigate = useNavigate();

    return <div className="sidebar">
        <div onClick={()=> navigate("/")} className="home-section">
        <FaHome size={40} />
        <p className="home-text">Home</p>
        </div>

        <div onClick={()=> navigate("/detect")} className="ddos-detection-section">
        <GiVirus  size={40} />
        <p className="ddos-table">Detect DDoS</p>
        </div>

        <div onClick={() => navigate("/geo-location")} className="ip-location-section">
        <IoMdGlobe size={40} />
        <p style={{"marginTop":"0px"}}>IP GeoLocation</p>
        </div>
    </div>

}
export default SideBar