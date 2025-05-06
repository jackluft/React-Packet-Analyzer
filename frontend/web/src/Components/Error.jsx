import { MdOutlineReportGmailerrorred } from "react-icons/md";
function Error({setError,setLoading}){
    return <div className="error-container">
    <MdOutlineReportGmailerrorred className="error-icon"  size={170}/>
    <h3 style={{"marginTop":"0px"}}>ERROR: Unable to analyze file</h3>
    <button className="error-button" onClick={() => {
        setError(false)
        setLoading(false)
    }}>Try again</button>
</div>


}
export default Error