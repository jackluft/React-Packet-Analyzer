import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import {createBrowserRouter, RouterProvider} from "react-router-dom"
import Home from './Components/Home'
import Detectpage from './Components/Detectpage'
import GeoPage from './Components/GeoPage.jsx'
import PageNotFound from './Components/PageNotFound.jsx'
const router = createBrowserRouter([
  {path: "/",element: <Home/>},
  {path: "detect",element: <Detectpage/>},
  {path: "geo-location",element: <GeoPage/>},
  {path: "*",element: <PageNotFound/>}
])

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <RouterProvider router={router}/>
  </StrictMode>,
)
