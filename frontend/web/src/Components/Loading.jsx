import "./Loading.css"
function Loading({txt}){
    return <div> 
    <div className="spinner"></div>
        <p>{txt}</p>
    </div>
}

export default Loading