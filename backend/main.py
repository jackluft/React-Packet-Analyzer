from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import shutil
import os
import json

from read_packets import readFile, analyse_ddos,ip_list
app = FastAPI()
origins = [
    "http://localhost:5174",  # Your frontend's actual origin
    "http://127.0.0.1:5174",  # Optional, for alternate access
]
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://localhost:\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
def checkPCAPExtension(fileName):
    extension = fileName.split(".")[-1]
    if(extension == "pcap"):
        return True
    return False
def removeFile(path):
    #Func: removeFile
    #Args: path -> Path for the file
    #Docs: This function will remove the file downloaded from the client
    if os.path.exists(path):
        os.remove(path)
@app.post("/upload/pcap")
async def upload_pcap(file: UploadFile = File(...)):
    filter = checkPCAPExtension(file.filename)
    if(filter == False):
        return JSONResponse(content={"ERROR": "Upload a pcap file"}, status_code=400)
    file_location = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_location, "wb") as f:
        shutil.copyfileobj(file.file, f)
    #File is downloaded now analyse the file
    results = readFile(file_location)
    #Remove file
    removeFile(file_location)
    return results



@app.post("/upload/detect-ddos")
async def detect_ddos(file: UploadFile = File(...)):
    filter = checkPCAPExtension(file.filename)
    if(filter == False):
        return JSONResponse(content={"ERROR": "Upload a pcap file"}, status_code=400)
    file_location = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_location, "wb") as f:
        shutil.copyfileobj(file.file, f)
    #File is downloaded
    results = analyse_ddos(file_location)
    removeFile(file_location)
    return results

@app.post("/list/ips")
async def get_ip_list(file: UploadFile = File(...)):
    filter = checkPCAPExtension(file.filename)
    if(filter == False):
        return JSONResponse(content={"ERROR": "Upload a pcap file"}, status_code=400)
    file_location = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_location, "wb") as f:
        shutil.copyfileobj(file.file, f)
    #File is downloaded
    results = ip_list(file_location)
    removeFile(file_location)
    return results



